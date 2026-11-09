package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestLoginRefusesAReturnAddressItDoesntAllow checks that a sign-in started on the hosted login
// can only be sent back to a path or an allowed origin, and to none at all while the hosted
// login isn't configured, before anything about the connection is read.
func TestLoginRefusesAReturnAddressItDoesntAllow(t *testing.T) {
	configured := &Service{}
	configured.SetHostedLogin("https://accounts.example.test", "https://api.example.test")
	for _, tc := range []struct {
		name     string
		service  *Service
		returnTo string
	}{
		{"another site", configured, "https://evil.example.test/oauth/authorize"},
		{"a protocol-relative address", configured, "//evil.example.test/x"},
		{"no hosted login configured", &Service{}, "https://api.example.test/oauth/authorize"},
	} {
		r := chi.NewRouter()
		(&Handler{Service: tc.service}).MountPublic(r)
		path := "/saml/login/" + uuid.NewString() + "?return_to=" + url.QueryEscape(tc.returnTo)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), errs.CodeSAMLReturnToInvalid) {
			t.Errorf("%s: %d %s, want 400 %s", tc.name, rec.Code, rec.Body.String(), errs.CodeSAMLReturnToInvalid)
		}
	}
}

// TestAFailedHostedSignInGoesBackToTheHostedLogin checks that a sign-in the hosted login began
// returns there with a generic error and its way back to the application when it fails, and that
// one without a stored return address, or with no hosted login configured, gets the error itself.
func TestAFailedHostedSignInGoesBackToTheHostedLogin(t *testing.T) {
	const accounts = "https://accounts.example.test"
	back := "https://api.example.test/oauth/authorize?client_id=portal&state=s1"
	configured := &Service{}
	configured.SetHostedLogin(accounts, "https://api.example.test")
	for _, tc := range []struct {
		name     string
		service  *Service
		returnTo string
		want     int
	}{
		{"a hosted sign-in", configured, back, http.StatusFound},
		{"a console sign-in", configured, "", http.StatusBadRequest},
		{"no hosted login configured", &Service{}, back, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/saml/acs/x", nil)
		(&Handler{Service: tc.service}).acsFailed(rec, req, uuid.New(), tc.returnTo, errs.ErrSAMLResponseMissing)
		if rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
			continue
		}
		if tc.want != http.StatusFound {
			continue
		}
		want := accounts + "/sign-in?" + url.Values{"error": {"sso"}, "return_to": {back}}.Encode()
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("%s: to %s, want %s", tc.name, got, want)
		}
		if strings.Contains(rec.Body.String(), errs.CodeSAMLResponseMissing) {
			t.Errorf("%s: the redirect names the detail: %s", tc.name, rec.Body.String())
		}
	}
}
