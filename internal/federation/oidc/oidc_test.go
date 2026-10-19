package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	// Non-localhost hosts default to https (real deploys terminate TLS at a proxy).
	if disc["issuer"] != "https://id.test" {
		t.Errorf("issuer = %v, want https://id.test", disc["issuer"])
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
	actorTypes, _ := disc["actor_types_supported"].([]any)
	if len(actorTypes) != 3 || actorTypes[2] != "agent" {
		t.Errorf("actor_types_supported = %v, want [user service agent]", actorTypes)
	}
}

func TestClientAuthenticatedEndpointsRejectOversizedForms(t *testing.T) {
	handler := &Handler{}
	router := chi.NewRouter()
	handler.MountPublic(router)
	body := "token=" + strings.Repeat("x", int(httpx.MaxFormBodyBytes)+1)

	for _, path := range []string{"/oauth/revoke", "/oauth/introspect"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", recorder.Code, recorder.Body.String())
			}
		})
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

func TestDownscope(t *testing.T) {
	subject := []string{"openid", "profile", "email"}

	// No requested scope → keep the subject's scopes.
	if got, ok := downscope(subject, ""); !ok || len(got) != 3 {
		t.Errorf("empty request should keep subject scopes, got %v ok=%v", got, ok)
	}
	// A strict subset is granted.
	if got, ok := downscope(subject, "openid email"); !ok || len(got) != 2 {
		t.Errorf("subset should be granted, got %v ok=%v", got, ok)
	}
	// Requesting a scope the subject lacks is rejected (no escalation).
	if _, ok := downscope(subject, "openid admin"); ok {
		t.Error("must reject a scope the subject token doesn't hold")
	}
	if _, ok := downscope(subject, "admin"); ok {
		t.Error("must reject escalation to a brand-new scope")
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
	if got := currentURL(req); got != "https://id.test/v1/oauth/authorize?client_id=rp&scope=openid" {
		t.Errorf("currentURL = %q", got)
	}
}

func TestValidateClientInput(t *testing.T) {
	valid := CreateClientInput{
		Type:           "confidential",
		RedirectURIs:   []string{"https://client.example/callback"},
		PostLogoutURIs: []string{"https://client.example/signed-out"},
		GrantTypes:     []string{"authorization_code", "refresh_token"},
	}
	if err := validateClientInput(valid); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
	loopback := valid
	loopback.Type = "public"
	loopback.RedirectURIs = []string{"http://127.0.0.1:49152/callback", "http://localhost:3000/callback"}
	if err := validateClientInput(loopback); err != nil {
		t.Fatalf("loopback native callback rejected: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*CreateClientInput)
	}{
		{"unknown client type", func(in *CreateClientInput) { in.Type = "browser" }},
		{"unknown grant", func(in *CreateClientInput) { in.GrantTypes = []string{"password"} }},
		{"authorization code without redirect", func(in *CreateClientInput) { in.RedirectURIs = nil }},
		{"non-loopback http redirect", func(in *CreateClientInput) { in.RedirectURIs = []string{"http://client.example/callback"} }},
		{"redirect fragment", func(in *CreateClientInput) { in.RedirectURIs = []string{"https://client.example/callback#fragment"} }},
		{"redirect userinfo", func(in *CreateClientInput) { in.RedirectURIs = []string{"https://user@client.example/callback"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if err := validateClientInput(in); err == nil {
				t.Fatal("invalid client input was accepted")
			}
		})
	}
}

func TestValidateRegisteredRedirectURI(t *testing.T) {
	valid := []string{
		"https://app.example.com/callback",
		"https://app.example.com/callback?next=%2Fhome",
		"http://127.0.0.1:8080/cb",
		"http://[::1]:8080/cb",
		"http://localhost:3000/cb",
		"com.example.app:/oauth2redirect",
		"com.example.app://oauth2redirect",
		"in.qeet.console:/cb",
	}
	for _, uri := range valid {
		if err := validateRegisteredRedirectURI(uri); err != nil {
			t.Errorf("validateRegisteredRedirectURI(%q) = %v, want nil", uri, err)
		}
	}

	invalid := []string{
		"",
		"/callback",                          // relative
		"https://app.example.com/cb#frag",    // fragment is the response's
		"https://user:pw@app.example.com/cb", // userinfo
		"http://example.com/cb",              // non-loopback cleartext
		"http://169.254.169.254/cb",          // link-local, not loopback
		"myapp:/cb",                          // no dot: not reverse-DNS
		"javascript:alert(1)",                // reserved scheme
		"data:text/html,x",                   // reserved scheme
		"ftp://example.com/cb",               // reserved scheme
		".com.example:/cb",                   // malformed scheme
		"com..example:/cb",                   // malformed scheme
	}
	for _, uri := range invalid {
		if err := validateRegisteredRedirectURI(uri); err == nil {
			t.Errorf("validateRegisteredRedirectURI(%q) = nil, want error", uri)
		}
	}
}

// A public client authenticates with a client_id alone, which is in every
// sign-in link, so it can't hold the flows that rely on client authentication.
func TestPublicClientsCantHoldConfidentialFlows(t *testing.T) {
	base := CreateClientInput{Type: "public", RedirectURIs: []string{"https://spa.example/cb"}}
	for _, grant := range []string{"token_exchange", grantTypeTokenExchange, grantTypeCIBA} {
		in := base
		in.GrantTypes = []string{"authorization_code", grant}
		if err := validateClientInput(in); !errors.Is(err, errs.ErrOIDCUnsupportedFlow) {
			t.Errorf("public + %s: err = %v, want %v", grant, err, errs.ErrOIDCUnsupportedFlow)
		}
		in.Type = "confidential"
		if err := validateClientInput(in); err != nil {
			t.Errorf("confidential + %s rejected: %v", grant, err)
		}
	}
}

// Discovery states which client authentication each endpoint accepts: a secret
// (Basic or form) everywhere, and none only where a public client may call.
func TestDiscovery_AdvertisesClientAuthMethods(t *testing.T) {
	h := &Handler{Service: NewService(nil, testIssuer(t))}
	r := chi.NewRouter()
	h.MountPublic(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	var disc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string][]string{
		"token_endpoint_auth_methods_supported":         {"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    {"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post"},
	}
	for key, methods := range want {
		got, _ := disc[key].([]any)
		if len(got) != len(methods) {
			t.Errorf("%s = %v, want %v", key, got, methods)
			continue
		}
		for i := range methods {
			if got[i] != methods[i] {
				t.Errorf("%s = %v, want %v", key, got, methods)
			}
		}
	}
}
