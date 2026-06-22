//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
)

// TestSigningKeysEndpoint proves GET /v1/oidc/signing-keys returns the issuer's
// active key with a kid + alg and no key material, and that the kid matches the
// issuer's active KID exposed via the JWKS.
func TestSigningKeysEndpoint(t *testing.T) {
	requireDB(t)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	h := &oidc.Handler{Service: svc}

	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		h.Mount(r)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/oidc/signing-keys")
	if err != nil {
		t.Fatalf("get signing-keys: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var body struct {
		Keys []struct {
			Kid    string `json:"kid"`
			Alg    string `json:"alg"`
			Use    string `json:"use"`
			Status string `json:"status"`
			// Any leaked key material would show up as extra fields; we assert
			// the known shape and that no x/y/d coordinates are present.
			X string `json:"x"`
			Y string `json:"y"`
			D string `json:"d"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Keys) != 1 {
		t.Fatalf("keys = %d, want exactly the active key", len(body.Keys))
	}
	k := body.Keys[0]
	if k.Kid == "" || k.Kid != issuer.KID() {
		t.Errorf("kid = %q, want issuer active KID %q", k.Kid, issuer.KID())
	}
	if k.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", k.Alg)
	}
	if k.Use != "sig" {
		t.Errorf("use = %q, want sig", k.Use)
	}
	if k.Status != "active" {
		t.Errorf("status = %q, want active", k.Status)
	}
	if k.X != "" || k.Y != "" || k.D != "" {
		t.Errorf("signing-keys must not expose key material: x=%q y=%q d=%q", k.X, k.Y, k.D)
	}
}
