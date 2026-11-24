// Package oidcrp is the OpenID Connect relying party behind single sign-on connections and social
// providers: it reads a provider's discovery document, trades an authorization code for tokens and
// checks the ID token against the provider's keys. Every request goes through the outbound policy;
// documents and keys are cached in memory.
package oidcrp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	discoveryTTL   = time.Hour        // how long a discovery document is reused
	keysTTL        = time.Hour        // how long a provider's signing keys are reused
	keysMinRefresh = 10 * time.Second // the least time between key fetches for an unknown key
	fetchTimeout   = 10 * time.Second // the longest a request to a provider may take
	maxBodyBytes   = 1 << 20          // the most of a provider's answer read
)

// Discovery is the part of a provider's discovery document a sign-in uses.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// signingKey is one of a provider's published signing keys.
type signingKey struct {
	kid string
	alg string // "" when the key may sign with any algorithm of its type
	key crypto.PublicKey
}

type cachedDiscovery struct {
	doc       Discovery
	expiresAt time.Time
}

type cachedKeys struct {
	keys      []signingKey
	fetchedAt time.Time
}

// Client talks to providers through the outbound policy.
type Client struct {
	http   *http.Client
	egress *egress.Policy
	now    func() time.Time
	mu     sync.Mutex
	docs   map[string]cachedDiscovery
	keys   map[string]cachedKeys
}

// New returns a client whose requests follow policy.
func New(policy *egress.Policy) *Client {
	return &Client{
		http:   policy.HTTPClient(fetchTimeout),
		egress: policy,
		now:    time.Now,
		docs:   map[string]cachedDiscovery{},
		keys:   map[string]cachedKeys{},
	}
}

// do sends req, whose URL must be an allowed outbound destination, and returns
// its status and at most maxBodyBytes of its body.
func (c *Client) do(req *http.Request) (int, []byte, error) {
	if _, err := c.egress.ValidateHTTPURL(req.URL.String()); err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req) // #nosec G704 -- destination checked by the outbound policy above
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return resp.StatusCode, body, err
}

// getJSON fetches rawURL and decodes its JSON body into out.
func (c *Client) getJSON(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) // #nosec G704 -- checked by do
	if err != nil {
		return err
	}
	status, body, err := c.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("%s: status %d", req.URL.Redacted(), status)
	}
	return json.Unmarshal(body, out)
}

// ErrDiscoveryInvalid marks a discovery document the provider served but a
// sign-in can't use.
var ErrDiscoveryInvalid = errors.New("discovery document unusable")

// Discover returns the provider's discovery document at rawURL, cached for
// discoveryTTL. A document without an issuer, token endpoint or keys, or whose
// authorization endpoint isn't https, is refused with ErrDiscoveryInvalid.
func (c *Client) Discover(ctx context.Context, rawURL string) (Discovery, error) {
	c.mu.Lock()
	hit, ok := c.docs[rawURL]
	c.mu.Unlock()
	if ok && c.now().Before(hit.expiresAt) {
		return hit.doc, nil
	}
	var doc Discovery
	if err := c.getJSON(ctx, rawURL, &doc); err != nil {
		return Discovery{}, err
	}
	if doc.Issuer == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return Discovery{}, fmt.Errorf("%w: issuer, token_endpoint and jwks_uri are required", ErrDiscoveryInvalid)
	}
	if !ValidAuthorizationEndpoint(doc.AuthorizationEndpoint) {
		return Discovery{}, fmt.Errorf("%w: authorization_endpoint must be an absolute https URL", ErrDiscoveryInvalid)
	}
	c.mu.Lock()
	c.docs[rawURL] = cachedDiscovery{doc: doc, expiresAt: c.now().Add(discoveryTTL)}
	c.mu.Unlock()
	return doc, nil
}

// ValidAuthorizationEndpoint reports whether raw is an absolute https URL with
// a host and no userinfo or fragment (RFC 6749 §3.1): the browser is sent there.
func ValidAuthorizationEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.Contains(raw, "#")
}

// AuthorizeURL returns endpoint with params added to its query.
func AuthorizeURL(endpoint string, params url.Values) string {
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}
	return endpoint + sep + params.Encode()
}

// signingKeys returns the provider's signing keys at jwksURI, cached for
// keysTTL. force fetches them again unless they were fetched within
// keysMinRefresh, so unknown keys can't make every sign-in fetch.
func (c *Client) signingKeys(ctx context.Context, jwksURI string, force bool) ([]signingKey, error) {
	c.mu.Lock()
	hit, ok := c.keys[jwksURI]
	c.mu.Unlock()
	age := c.now().Sub(hit.fetchedAt)
	if ok && (age < keysMinRefresh || (!force && age < keysTTL)) {
		return hit.keys, nil
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := c.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, err
	}
	keys := make([]signingKey, 0, len(set.Keys))
	for _, raw := range set.Keys {
		if k, ok := parseJWK(raw); ok {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	c.mu.Lock()
	c.keys[jwksURI] = cachedKeys{keys: keys, fetchedAt: c.now()}
	c.mu.Unlock()
	return keys, nil
}

// verificationKey returns the key named kid that verifies a signature made
// with alg. A kid not among the cached keys fetches them again once, as a
// provider rotating its keys publishes the new one before signing with it.
func (c *Client) verificationKey(ctx context.Context, jwksURI, kid, alg string) (crypto.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("jwks: the token names no key")
	}
	keys, err := c.signingKeys(ctx, jwksURI, false)
	if err != nil {
		return nil, err
	}
	if key := pickKey(keys, kid, alg); key != nil {
		return key, nil
	}
	if keys, err = c.signingKeys(ctx, jwksURI, true); err != nil {
		return nil, err
	}
	if key := pickKey(keys, kid, alg); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("jwks: no %s key with kid %q", alg, kid)
}

// pickKey returns the key named kid that may sign with alg.
func pickKey(keys []signingKey, kid, alg string) crypto.PublicKey {
	for _, k := range keys {
		if k.kid == kid && (k.alg == "" || k.alg == alg) && keyFits(k.key, alg) {
			return k.key
		}
	}
	return nil
}

// keyFits reports whether key is of the type and size alg signs with.
func keyFits(key crypto.PublicKey, alg string) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		switch alg {
		case "ES256":
			return k.Curve == elliptic.P256()
		case "ES384":
			return k.Curve == elliptic.P384()
		case "ES512":
			return k.Curve == elliptic.P521()
		}
	}
	return false
}

// parseJWK returns the RSA or EC signing key raw describes. Keys without a
// kid, encryption keys, RSA keys under 2048 bits and points off their curve
// are skipped.
func parseJWK(raw json.RawMessage) (signingKey, bool) {
	var j struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &j); err != nil || j.Kid == "" || (j.Use != "" && j.Use != "sig") {
		return signingKey{}, false
	}
	if j.Alg != "" && !slices.Contains(SigningAlgorithms, j.Alg) {
		return signingKey{}, false
	}
	out := signingKey{kid: j.Kid, alg: j.Alg}
	switch j.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return signingKey{}, false
		}
		e, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return signingKey{}, false
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
		if key.N.BitLen() < 2048 || key.E < 3 || key.E%2 == 0 {
			return signingKey{}, false
		}
		out.key = key
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return signingKey{}, false
		}
		size := (curve.Params().BitSize + 7) / 8
		x, errX := base64.RawURLEncoding.DecodeString(j.X)
		y, errY := base64.RawURLEncoding.DecodeString(j.Y)
		if errX != nil || errY != nil || len(x) != size || len(y) != size {
			return signingKey{}, false
		}
		key, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return signingKey{}, false
		}
		out.key = key
	default:
		return signingKey{}, false
	}
	return out, true
}

// Credentials are how the client authenticates at the token endpoint.
type Credentials struct {
	ClientID, ClientSecret string
}

// Tokens are what the token endpoint answered with.
type Tokens struct {
	IDToken     string
	AccessToken string
}

// Exchange trades an authorization code for the provider's tokens; verifier is
// the PKCE verifier ("" when the sign-in sent none). The client authenticates
// with HTTP Basic, the default, unless the provider supports only sending the
// secret in the form.
func (c *Client) Exchange(ctx context.Context, doc Discovery, cred Credentials, code, redirectURI, verifier string) (Tokens, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	basic := len(doc.TokenAuthMethods) == 0 || slices.Contains(doc.TokenAuthMethods, "client_secret_basic")
	if !basic {
		form.Set("client_id", cred.ClientID)
		form.Set("client_secret", cred.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode())) // #nosec G704 -- checked by do
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		// RFC 6749 §2.3.1: both are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(cred.ClientID), url.QueryEscape(cred.ClientSecret))
	}
	status, body, err := c.do(req)
	if err != nil {
		return Tokens{}, err
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil && status == http.StatusOK {
		return Tokens{}, err
	}
	if status != http.StatusOK {
		return Tokens{}, fmt.Errorf("token endpoint: status %d %s", status, SafeErrorCode(tok.Error))
	}
	return Tokens{IDToken: tok.IDToken, AccessToken: tok.AccessToken}, nil
}

// Userinfo reads the provider's userinfo for accessToken into out.
func (c *Client) Userinfo(ctx context.Context, doc Discovery, accessToken string, out any) error {
	if doc.UserinfoEndpoint == "" {
		return errors.New("provider has no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil) // #nosec G704 -- checked by do
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	status, body, err := c.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("userinfo: status %d", status)
	}
	return json.Unmarshal(body, out)
}

// SafeErrorCode returns code when it is a short OAuth error code, else "", so
// a provider's answer can be logged or recorded without carrying anything else.
func SafeErrorCode(code string) string {
	if len(code) > 64 {
		return ""
	}
	for i := 0; i < len(code); i++ {
		if c := code[i]; (c < 'a' || c > 'z') && c != '_' {
			return ""
		}
	}
	return code
}
