// Package oidcrptest is a fake OpenID Connect provider for tests of the
// sign-ins oidcrp drives: a discovery document, published signing keys, a
// token endpoint redeeming the codes a test prepares, and userinfo.
package oidcrptest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// AuthorizeEndpoint is where the provider's discovery document sends browsers.
const AuthorizeEndpoint = "https://idp.example.test/authorize"

// Grant is an authorization code the token endpoint will redeem once: for
// ClientID (the provider's when ""), and the PKCE challenge and redirect URI
// it was issued for, when set, with IDToken, and an access token that reads
// Userinfo.
type Grant struct {
	ClientID    string
	Challenge   string
	RedirectURI string
	IDToken     string
	Userinfo    any
}

// Provider is the fake provider. Its issuer is its URL unless changed.
type Provider struct {
	*httptest.Server
	ClientID, ClientSecret string
	mu                     sync.Mutex
	issuer                 string
	authMethods            []string
	key                    crypto.Signer
	kid                    string
	published              []map[string]string
	jwksFetches            int
	pending                map[string]Grant
	userinfo               map[string]any
}

// New starts a provider for clientID, signing with a fresh RSA key, until t ends.
func New(t testing.TB, clientID, clientSecret string) *Provider {
	t.Helper()
	p := &Provider{ClientID: clientID, ClientSecret: clientSecret, pending: map[string]Grant{}, userinfo: map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.jwksFetches++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": p.published})
	})
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		info, ok := p.userinfo[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		p.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(info)
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	p.issuer = p.URL
	p.Rotate(t, "key-1")
	return p
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := map[string]any{
		"issuer":                 p.issuer,
		"authorization_endpoint": AuthorizeEndpoint,
		"token_endpoint":         p.URL + "/token",
		"userinfo_endpoint":      p.URL + "/userinfo",
		"jwks_uri":               p.URL + "/jwks",
	}
	if p.authMethods != nil {
		doc["token_endpoint_auth_methods_supported"] = p.authMethods
	}
	_ = json.NewEncoder(w).Encode(doc)
}

// DiscoveryURL is where the provider's discovery document is served.
func (p *Provider) DiscoveryURL() string { return p.URL + "/.well-known/openid-configuration" }

// JWKSURL is where the provider's signing keys are published.
func (p *Provider) JWKSURL() string { return p.URL + "/jwks" }

// Issuer is the issuer the discovery document names.
func (p *Provider) Issuer() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.issuer
}

// SetIssuer changes the issuer the discovery document names.
func (p *Provider) SetIssuer(issuer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.issuer = issuer
}

// SetAuthMethods sets the token endpoint authentication methods the discovery
// document lists (nil: none listed).
func (p *Provider) SetAuthMethods(methods []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authMethods = methods
}

// Rotate signs with a fresh RSA key named kid from now on, publishing only it.
func (p *Provider) Rotate(t testing.TB, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.kid = key, kid
	p.published = []map[string]string{RSAJWK(kid, &key.PublicKey)}
}

// Publish adds jwk to the published keys.
func (p *Provider) Publish(jwk map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.published = append(p.published, jwk)
}

// Fetches is how often the provider's keys were read.
func (p *Provider) Fetches() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksFetches
}

// Claims returns the claims of a correct ID token for the provider's client
// with nonce, from its issuer.
func (p *Provider) Claims(nonce, sub, email string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": p.Issuer(), "aud": p.ClientID, "sub": sub, "nonce": nonce,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"email": email, "email_verified": true, "name": "Asha Rao",
	}
}

// Sign returns claims signed with the provider's current key, or with signer
// under kid when signer is given.
func (p *Provider) Sign(t testing.TB, claims jwt.MapClaims, signer crypto.Signer, kid string) string {
	t.Helper()
	p.mu.Lock()
	if signer == nil {
		signer, kid = p.key, p.kid
	}
	p.mu.Unlock()
	method := jwt.SigningMethod(jwt.SigningMethodRS256)
	if _, ok := signer.(*ecdsa.PrivateKey); ok {
		method = jwt.SigningMethodES256
	}
	token := jwt.NewWithClaims(method, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(signer)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Expect makes the token endpoint redeem code once, as g says.
func (p *Provider) Expect(code string, g Grant) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[code] = g
}

// token redeems a prepared code for the client, authenticated with its secret
// by HTTP Basic or in the form.
func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, ok := p.pending[code]
	delete(p.pending, code)
	p.mu.Unlock()
	client := p.ClientID
	if g.ClientID != "" {
		client = g.ClientID
	}
	switch {
	case id != client || secret != p.ClientSecret:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
	case !ok || r.PostForm.Get("grant_type") != "authorization_code" ||
		(g.Challenge != "" && codes.Hash(r.PostForm.Get("code_verifier")) != g.Challenge) ||
		(g.RedirectURI != "" && r.PostForm.Get("redirect_uri") != g.RedirectURI):
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	default:
		access := "at-" + code
		p.mu.Lock()
		p.userinfo[access] = g.Userinfo
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": access, "token_type": "Bearer", "id_token": g.IDToken})
	}
}

// RSAJWK is key published under kid for RS256.
func RSAJWK(kid string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kid": kid, "kty": "RSA", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// ECJWK is a P-256 key published under kid for ES256.
func ECJWK(kid string, key *ecdsa.PublicKey) map[string]string {
	raw, err := key.Bytes()
	if err != nil {
		panic(err)
	}
	size := (len(raw) - 1) / 2
	return map[string]string{
		"kid": kid, "kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(raw[1 : 1+size]),
		"y": base64.RawURLEncoding.EncodeToString(raw[1+size:]),
	}
}
