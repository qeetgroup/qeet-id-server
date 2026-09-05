//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
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

// TestSigningKeyRotationIsNotMounted proves that process-local signing-key
// rotation and private-key export are not exposed through the application API.
func TestSigningKeyRotationIsNotMounted(t *testing.T) {
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

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/oidc/signing-keys/rotate", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post signing-key rotation: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for removed signing-key rotation route", resp.StatusCode)
	}
	if issuer.KID() == "" {
		t.Fatal("configured issuer must remain usable after the rejected request")
	}
}
