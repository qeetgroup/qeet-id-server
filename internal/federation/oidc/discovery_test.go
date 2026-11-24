package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// TestProtectedResourceMetadataNamesTheIssuer checks that the RFC 9728
// document names as its authorization server the issuer the tokens carry, the
// identifier a client looks the server's metadata up by, not the host the
// request came in on behind a proxy.
func TestProtectedResourceMetadataNamesTheIssuer(t *testing.T) {
	key, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := tokens.NewIssuer(key, "https://id.qeet.example", "https://id.qeet.example", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	(&Handler{Service: newTestService(t, new(pgxpool.Pool), issuer)}).MountPublic(r)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	req.Host = "internal-lb.example:8080"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var doc struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("protected-resource metadata: %d %s", rec.Code, rec.Body.String())
	}
	if !slices.Equal(doc.AuthorizationServers, []string{"https://id.qeet.example"}) {
		t.Errorf("authorization_servers %v, want the issuer [https://id.qeet.example]", doc.AuthorizationServers)
	}
}

// TestDiscovery_AdvertisesAlgIssuerS256 covers the alg/issuer/PKCE-method
// metadata an RP reads to configure verification. No DB needed.
func TestDiscovery_AdvertisesAlgIssuerS256(t *testing.T) {
	issuer := testIssuer(t)
	h := &Handler{Service: newTestService(t, new(pgxpool.Pool), issuer)}
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
	// One token endpoint serves every grant, the machine identities'
	// client_credentials too.
	if disc["token_endpoint"] != "https://id.test/v1/oauth/token" {
		t.Errorf("token_endpoint = %v, want https://id.test/v1/oauth/token", disc["token_endpoint"])
	}
	grants, _ := disc["grant_types_supported"].([]any)
	want := []any{"authorization_code", "refresh_token", grantTypeDeviceCode, grantTypeTokenExchange, grantTypeCIBA, grantTypeClientCredentials}
	if !slices.Equal(grants, want) {
		t.Errorf("grant_types_supported = %v, want %v", grants, want)
	}
	actorTypes, _ := disc["actor_types_supported"].([]any)
	if len(actorTypes) != 3 || actorTypes[2] != "agent" {
		t.Errorf("actor_types_supported = %v, want [user service agent]", actorTypes)
	}
	if scopes, _ := disc["scopes_supported"].([]any); !slices.Contains(scopes, any("offline_access")) || !slices.Contains(scopes, any("openid")) {
		t.Errorf("scopes_supported = %v, want openid and offline_access among them", scopes)
	}
}

// TestDiscovery_AdvertisesClientAuthMethods checks that discovery lists the
// client authentication each endpoint accepts.
func TestDiscovery_AdvertisesClientAuthMethods(t *testing.T) {
	h := &Handler{Service: newTestService(t, new(pgxpool.Pool), testIssuer(t))}
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

// TestJWKSEndpoint_ServesActivePublicKey proves the provider surface a relying
// party depends on: /.well-known/jwks.json publishes the active public key
// (kid == token kid) and discovery advertises its algorithm, ES256 for an EC
// key and RS256 for an RSA key. No DB needed — these handlers only read the
// issuer.
func TestJWKSEndpoint_ServesActivePublicKey(t *testing.T) {
	ecKeyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	rsaKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, c := range []struct{ keyPEM, kty, alg string }{
		{ecKeyPEM, "EC", "ES256"},
		{rsaKeyPEM, "RSA", "RS256"},
	} {
		issuer, err := tokens.NewIssuer(c.keyPEM, "https://id.test", "https://id.test", 15*time.Minute, time.Hour)
		if err != nil {
			t.Fatalf("%s: issuer: %v", c.alg, err)
		}
		h := &Handler{Service: newTestService(t, new(pgxpool.Pool), issuer)}

		r := chi.NewRouter()
		h.MountPublic(r)

		// --- JWKS ---
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: jwks status = %d", c.alg, rec.Code)
		}
		var jwks struct {
			Keys []tokens.JWK `json:"keys"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
			t.Fatalf("%s: decode jwks: %v", c.alg, err)
		}
		if len(jwks.Keys) != 1 {
			t.Fatalf("%s: jwks keys = %d, want 1", c.alg, len(jwks.Keys))
		}
		k := jwks.Keys[0]
		if k.Kid != issuer.KID() || k.Kty != c.kty || k.Alg != c.alg || k.Use != "sig" {
			t.Errorf("%s: unexpected jwk: %+v (active kid %s)", c.alg, k, issuer.KID())
		}
		ec := k.Crv == "P-256" && k.X != "" && k.Y != "" && k.N == "" && k.E == ""
		rsaShaped := k.N != "" && k.E != "" && k.Crv == "" && k.X == "" && k.Y == ""
		if ec != (c.kty == "EC") || rsaShaped != (c.kty == "RSA") {
			t.Errorf("%s: jwk %+v, want only an %s key's members", c.alg, k, c.kty)
		}

		// --- Discovery advertises the key's algorithm ---
		rec = httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: discovery status = %d", c.alg, rec.Code)
		}
		var disc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
			t.Fatalf("%s: decode discovery: %v", c.alg, err)
		}
		algs, _ := disc["id_token_signing_alg_values_supported"].([]any)
		if len(algs) != 1 || algs[0] != c.alg {
			t.Errorf("discovery alg = %v, want [%s]", disc["id_token_signing_alg_values_supported"], c.alg)
		}
	}
}
