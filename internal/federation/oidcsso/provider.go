package oidcsso

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

// discovery is the part of a provider's OpenID Connect discovery document a
// sign-in uses.
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

// signingKey is one of a provider's published signing keys.
type signingKey struct {
	kid string // "" when the provider names none
	alg string // "" when the key may sign with any algorithm of its type
	key crypto.PublicKey
}

type cachedDiscovery struct {
	doc       discovery
	expiresAt time.Time
}

type cachedKeys struct {
	keys      []signingKey
	fetchedAt time.Time
}

// providerClient talks to organisations' providers through the outbound
// policy, caching their discovery documents and signing keys in memory.
type providerClient struct {
	http   *http.Client
	egress *egress.Policy
	now    func() time.Time
	mu     sync.Mutex
	docs   map[string]cachedDiscovery
	keys   map[string]cachedKeys
}

func newProviderClient(policy *egress.Policy) *providerClient {
	return &providerClient{
		http:   policy.HTTPClient(fetchTimeout),
		egress: policy,
		now:    time.Now,
		docs:   map[string]cachedDiscovery{},
		keys:   map[string]cachedKeys{},
	}
}

// getJSON fetches rawURL, which must be an allowed outbound destination, and
// decodes its JSON body into out.
func (c *providerClient) getJSON(ctx context.Context, rawURL string, out any) error {
	if _, err := c.egress.ValidateHTTPURL(rawURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) // #nosec G704 -- destination checked by the outbound policy above
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req) // #nosec G704 -- destination checked by the outbound policy
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", rawURL, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(out)
}

// errDiscoveryInvalid marks a discovery document the provider served but a
// sign-in can't use.
var errDiscoveryInvalid = errors.New("discovery document unusable")

// discover returns the provider's discovery document at rawURL, cached for
// discoveryTTL. A document without an issuer, token endpoint or keys, or whose
// authorization endpoint isn't https, is refused with errDiscoveryInvalid.
func (c *providerClient) discover(ctx context.Context, rawURL string) (discovery, error) {
	c.mu.Lock()
	hit, ok := c.docs[rawURL]
	c.mu.Unlock()
	if ok && c.now().Before(hit.expiresAt) {
		return hit.doc, nil
	}
	var doc discovery
	if err := c.getJSON(ctx, rawURL, &doc); err != nil {
		return discovery{}, err
	}
	if doc.Issuer == "" || doc.TokenEndpoint == "" || doc.JWKSURI == "" {
		return discovery{}, fmt.Errorf("%w: issuer, token_endpoint and jwks_uri are required", errDiscoveryInvalid)
	}
	if !validAuthorizationEndpoint(doc.AuthorizationEndpoint) {
		return discovery{}, fmt.Errorf("%w: authorization_endpoint must be an absolute https URL", errDiscoveryInvalid)
	}
	c.mu.Lock()
	c.docs[rawURL] = cachedDiscovery{doc: doc, expiresAt: c.now().Add(discoveryTTL)}
	c.mu.Unlock()
	return doc, nil
}

// validAuthorizationEndpoint reports whether raw is an absolute https URL with
// a host and no userinfo or fragment (RFC 6749 §3.1): the browser is sent there.
func validAuthorizationEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && !strings.Contains(raw, "#")
}

// signingKeys returns the provider's signing keys at jwksURI, cached for
// keysTTL. force fetches them again unless they were fetched within
// keysMinRefresh, so unknown keys can't make every sign-in fetch.
func (c *providerClient) signingKeys(ctx context.Context, jwksURI string, force bool) ([]signingKey, error) {
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

// verificationKey returns the key that verifies a signature made with alg
// under kid. A kid not among the cached keys fetches them again once, as a
// provider rotating its keys publishes the new one before signing with it.
func (c *providerClient) verificationKey(ctx context.Context, jwksURI, kid, alg string) (crypto.PublicKey, error) {
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

// pickKey returns the key named kid that may sign with alg, or, when the token
// names no key, the only key there is.
func pickKey(keys []signingKey, kid, alg string) crypto.PublicKey {
	var candidates []signingKey
	if kid == "" {
		if len(keys) == 1 {
			candidates = keys
		}
	} else {
		for _, k := range keys {
			if k.kid == kid {
				candidates = append(candidates, k)
			}
		}
	}
	for _, k := range candidates {
		if (k.alg == "" || k.alg == alg) && keyFits(k.key, alg) {
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

// parseJWK returns the RSA or EC signing key raw describes. Encryption keys,
// RSA keys under 2048 bits and points off their curve are skipped.
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
	if err := json.Unmarshal(raw, &j); err != nil || (j.Use != "" && j.Use != "sig") {
		return signingKey{}, false
	}
	if j.Alg != "" && !slices.Contains(signingAlgs, j.Alg) {
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

// exchangeCode trades an authorization code for the provider's ID token. The
// client authenticates with HTTP Basic, the default, unless the provider
// supports only sending the secret in the form.
func (c *providerClient) exchangeCode(ctx context.Context, doc discovery, clientID, clientSecret, code, redirectURI, verifier string) (string, error) {
	if _, err := c.egress.ValidateHTTPURL(doc.TokenEndpoint); err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	basic := len(doc.TokenAuthMethods) == 0 || slices.Contains(doc.TokenAuthMethods, "client_secret_basic")
	if !basic {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, doc.TokenEndpoint, strings.NewReader(form.Encode())) // #nosec G704 -- destination checked by the outbound policy above
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 §2.3.1: both are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	resp, err := c.http.Do(req) // #nosec G704 -- destination checked by the outbound policy
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&tok); err != nil && resp.StatusCode == http.StatusOK {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: status %d %s", resp.StatusCode, safeCode(tok.Error))
	}
	if tok.IDToken == "" {
		return "", errors.New("token endpoint: no id_token")
	}
	return tok.IDToken, nil
}

// safeCode returns code when it is a short OAuth error code, else "", so a
// provider's answer can be logged without carrying anything else.
func safeCode(code string) string {
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
