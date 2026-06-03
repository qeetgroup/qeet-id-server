package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
)

// TestJWKSEndpoint_ServesActivePublicKey proves the provider surface a relying
// party depends on: /.well-known/jwks.json publishes the active ES256 public
// key (kid == token kid) and discovery advertises ES256. No DB needed — these
// handlers only read the issuer.
func TestJWKSEndpoint_ServesActivePublicKey(t *testing.T) {
	keyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	issuer, err := tokens.NewIssuer(keyPEM, "https://id.test", "https://id.test", 15*time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	h := &Handler{Service: NewService(nil, issuer)}

	r := chi.NewRouter()
	h.MountPublic(r)

	// --- JWKS ---
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks status = %d", rec.Code)
	}
	var jwks struct {
		Keys []tokens.JWK `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("jwks keys = %d, want 1", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kid != issuer.KID() || k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Errorf("unexpected jwk: %+v (active kid %s)", k, issuer.KID())
	}
	if k.X == "" || k.Y == "" {
		t.Error("jwk must carry x/y coordinates")
	}

	// --- Discovery advertises ES256 ---
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", rec.Code)
	}
	var disc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	algs, _ := disc["id_token_signing_alg_values_supported"].([]any)
	if len(algs) != 1 || algs[0] != "ES256" {
		t.Errorf("discovery alg = %v, want [ES256]", disc["id_token_signing_alg_values_supported"])
	}
}
