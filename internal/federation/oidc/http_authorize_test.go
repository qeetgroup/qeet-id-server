package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// TestAuthorizeTakesItsParametersByPOST checks that the authorization endpoint
// accepts a form POST, as OpenID Connect Core 3.1.2.1 requires, and goes on as
// the same request by GET, where the sign-in cookie a cross-site POST doesn't
// carry is read.
func TestAuthorizeTakesItsParametersByPOST(t *testing.T) {
	h := &Handler{PublicBaseURL: "https://id.example.test"}
	r := chi.NewRouter()
	r.Route("/v1", h.MountBrowser)
	form := url.Values{
		"client_id": {"app"}, "redirect_uri": {"https://app.example.test/cb?x=1"}, "response_type": {"code"},
		"scope": {"openid email"}, "state": {"s 1&x=y"}, "nonce": {"n-1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST to the authorization endpoint: %d %s, want 303", rec.Code, rec.Body.String())
	}
	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := to.Scheme + "://" + to.Host + to.Path; got != "https://id.example.test/v1/oauth/authorize" {
		t.Errorf("goes on at %s, want this server's authorization endpoint", got)
	}
	if !reflect.DeepEqual(to.Query(), form) {
		t.Errorf("goes on with %v, want the posted parameters %v", to.Query(), form)
	}
}
