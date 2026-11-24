package oidcsso

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// fakeIdP is an organization's OpenID Connect provider: a discovery document,
// its published signing keys and a token endpoint answering the codes a test
// prepares with ID tokens it signs.
type fakeIdP struct {
	*httptest.Server
	mu          sync.Mutex
	issuer      string // the discovery document's issuer; the server's URL unless changed
	key         crypto.Signer
	kid         string
	published   []map[string]string
	authMethods []string
	pending     map[string]pendingCode
}

// pendingCode is an authorization code the token endpoint will redeem.
type pendingCode struct {
	challenge   string
	redirectURI string
	token       string
}

// newFakeIdP starts a provider signing with a fresh RSA key until t ends.
func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	p := &fakeIdP{pending: map[string]pendingCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		doc := map[string]any{
			"issuer":                 p.issuer,
			"authorization_endpoint": testAuthorizeBase,
			"token_endpoint":         p.URL + "/token",
			"jwks_uri":               p.URL + "/jwks",
		}
		if p.authMethods != nil {
			doc["token_endpoint_auth_methods_supported"] = p.authMethods
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": p.published})
	})
	mux.HandleFunc("/token", p.token)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	p.issuer = p.URL
	p.rotate(t, "key-1")
	return p
}

// rotate signs with a fresh RSA key named kid from now on, publishing only it.
func (p *fakeIdP) rotate(t *testing.T, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.kid = key, kid
	p.published = []map[string]string{rsaJWK(kid, &key.PublicKey)}
}

func rsaJWK(kid string, key *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kid": kid, "kty": "RSA", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

// newECKey returns a P-256 signing key.
func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// claimsFor returns the claims of a correct ID token for clientID with nonce,
// from the provider's issuer.
func (p *fakeIdP) claimsFor(nonce, sub, email string) jwt.MapClaims {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	return jwt.MapClaims{
		"iss": p.issuer, "aud": testClientID, "sub": sub, "nonce": nonce,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		"email": email, "email_verified": true, "name": "Asha Rao",
	}
}

// sign returns claims signed with the provider's current key, or with signer
// under kid when signer is given.
func (p *fakeIdP) sign(t *testing.T, claims jwt.MapClaims, signer crypto.Signer, kid string) string {
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

// token redeems a prepared code for a client that authenticates with its
// secret and presents the code's PKCE verifier and redirect URI.
func (p *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
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
	p.mu.Lock()
	pending, ok := p.pending[r.PostForm.Get("code")]
	delete(p.pending, r.PostForm.Get("code"))
	p.mu.Unlock()
	switch {
	case id != testClientID || secret != testClientSecret:
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
	case !ok || r.PostForm.Get("grant_type") != "authorization_code" ||
		codes.Hash(r.PostForm.Get("code_verifier")) != pending.challenge || r.PostForm.Get("redirect_uri") != pending.redirectURI:
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "token_type": "Bearer", "id_token": pending.token})
	}
}

const (
	testClientID      = "qeet-client"
	testClientSecret  = "qeet-client-secret" // #nosec G101 -- a test fixture
	testAuthorizeBase = "https://idp.example.test/authorize"
)
