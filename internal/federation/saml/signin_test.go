package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	samltypes "github.com/russellhaering/gosaml2/types"
)

// TestWithinValidityAllowsClockSkew checks that an assertion's Conditions are
// met up to assertionClockSkew before NotBefore and after NotOnOrAfter, and
// that one without readable Conditions is not.
func TestWithinValidityAllowsClockSkew(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	window := func(notBefore, notOnOrAfter time.Duration) []samltypes.Assertion {
		return []samltypes.Assertion{{Conditions: &samltypes.Conditions{
			NotBefore: now.Add(notBefore).Format(time.RFC3339), NotOnOrAfter: now.Add(notOnOrAfter).Format(time.RFC3339),
		}}}
	}
	for _, c := range []struct {
		name       string
		assertions []samltypes.Assertion
		want       bool
	}{
		{"current", window(-time.Minute, 5*time.Minute), true},
		{"two minutes early", window(2*time.Minute, 10*time.Minute), true},
		{"five minutes early", window(5*time.Minute, 10*time.Minute), false},
		{"expired two minutes ago", window(-10*time.Minute, -2*time.Minute), true},
		{"expired five minutes ago", window(-10*time.Minute, -5*time.Minute), false},
		{"one current, one expired", append(window(-time.Minute, 5*time.Minute), window(-10*time.Minute, -5*time.Minute)...), false},
		{"no conditions", []samltypes.Assertion{{}}, false},
		{"unreadable times", []samltypes.Assertion{{Conditions: &samltypes.Conditions{NotBefore: "soon", NotOnOrAfter: "later"}}}, false},
		{"no assertions", nil, false},
	} {
		if got := withinValidity(c.assertions, now); got != c.want {
			t.Errorf("%s: withinValidity = %t, want %t", c.name, got, c.want)
		}
	}
}

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
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), CodeReturnToInvalid) {
			t.Errorf("%s: %d %s, want 400 %s", tc.name, rec.Code, rec.Body.String(), CodeReturnToInvalid)
		}
	}
}
