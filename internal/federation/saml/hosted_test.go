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
