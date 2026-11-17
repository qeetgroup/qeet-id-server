package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

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
		h := &Handler{Service: NewService(nil, issuer)}

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
