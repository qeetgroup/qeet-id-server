package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

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
	(&Handler{Service: NewService(nil, issuer)}).MountPublic(r)
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
