package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
)

func testIssuer(t *testing.T) *tokens.Issuer {
	t.Helper()
	keyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	i, err := tokens.NewIssuer(keyPEM, "https://id.test", "https://id.test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return i
}

// TestPKCE_S256ChallengeDerivation pins the exact relationship the
// authorization-code exchange relies on: the stored code_challenge equals
// BASE64URL(SHA256(verifier)) with no padding — i.e. codes.Hash(verifier).
// ExchangeCode accepts a presented verifier iff codes.Hash(verifier) matches
// the stored challenge, so this is the heart of PKCE S256 verification.
func TestPKCE_S256ChallengeDerivation(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 §A.1 verifier
	challenge := codes.Hash(verifier)

	// Independently compute the canonical S256 challenge and compare.
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != want {
		t.Fatalf("codes.Hash(verifier) = %q, want canonical S256 %q", challenge, want)
	}
	// No base64 padding (PKCE challenges are unpadded base64url).
	if strings.Contains(challenge, "=") {
		t.Errorf("S256 challenge must be unpadded base64url, got %q", challenge)
	}

	// The verification predicate ExchangeCode uses: a matching verifier passes,
	// a tampered one fails.
	if codes.Hash(verifier) != challenge {
		t.Error("the correct verifier must reproduce the challenge")
	}
	if codes.Hash(verifier+"x") == challenge {
		t.Error("a tampered verifier must not reproduce the challenge")
	}
}

// TestDiscovery_AdvertisesAlgIssuerS256 covers the alg/issuer/PKCE-method
// metadata an RP reads to configure verification. No DB needed.
func TestDiscovery_AdvertisesAlgIssuerS256(t *testing.T) {
	issuer := testIssuer(t)
	h := &Handler{Service: NewService(nil, issuer)}
	r := chi.NewRouter()
	h.MountPublic(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Host = "id.test"
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", rec.Code)
	}
	var disc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if disc["issuer"] != "http://id.test" {
		t.Errorf("issuer = %v, want http://id.test", disc["issuer"])
	}
	algs, _ := disc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != issuer.Alg() {
		t.Errorf("alg = %v, want [%s]", algs, issuer.Alg())
	}
	pkce, _ := disc["code_challenge_methods_supported"].([]any)
	if len(pkce) != 1 || pkce[0] != "S256" {
		t.Errorf("code_challenge_methods = %v, want [S256]", pkce)
	}
	// Only the authorization-code/refresh/client-credentials grants are advertised.
	grants, _ := disc["grant_types_supported"].([]any)
	if len(grants) == 0 {
		t.Error("discovery must advertise grant_types_supported")
	}
}

func TestContains(t *testing.T) {
	hay := []string{"openid", "profile", "email"}
	for _, want := range hay {
		if !contains(hay, want) {
			t.Errorf("contains should find %q", want)
		}
	}
	if contains(hay, "address") {
		t.Error("contains must not report a missing scope")
	}
	if contains(nil, "openid") {
		t.Error("contains over nil must be false")
	}
}

func TestDerefStr(t *testing.T) {
	if derefStr(nil) != "" {
		t.Error("derefStr(nil) must be empty")
	}
	s := "nonce-123"
	if derefStr(&s) != "nonce-123" {
		t.Error("derefStr must return the pointee")
	}
}

func TestAppendQuery(t *testing.T) {
	cases := []struct {
		name string
		base string
		kv   []string
		want string
	}{
		{"no existing query", "https://rp/cb", []string{"code", "abc"}, "https://rp/cb?code=abc"},
		{"existing query uses &", "https://rp/cb?x=1", []string{"code", "abc"}, "https://rp/cb?x=1&code=abc"},
		{"skips empty values", "https://rp/cb", []string{"code", "abc", "state", ""}, "https://rp/cb?code=abc"},
		{"escapes values", "https://rp/cb", []string{"state", "a b&c"}, "https://rp/cb?state=a+b%26c"},
		{"multiple pairs", "https://rp/cb", []string{"code", "c", "state", "s"}, "https://rp/cb?code=c&state=s"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appendQuery(c.base, c.kv...); got != c.want {
				t.Errorf("appendQuery(%q, %v) = %q, want %q", c.base, c.kv, got, c.want)
			}
		})
	}
}

func TestCurrentURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/authorize?client_id=rp&scope=openid", nil)
	req.Host = "id.test"
	if got := currentURL(req); got != "http://id.test/v1/oauth/authorize?client_id=rp&scope=openid" {
		t.Errorf("currentURL = %q", got)
	}
}
