package adminportal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestNormalizeCapabilities(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{name: "empty", in: nil, wantErr: true},
		{name: "unknown", in: []string{"ldap"}, wantErr: true},
		{name: "single", in: []string{"saml"}, want: []string{"saml"}},
		{name: "both, mixed case and whitespace", in: []string{" SAML", "scim "}, want: []string{"saml", "scim"}},
		{name: "dedupes", in: []string{"saml", "saml", "scim"}, want: []string{"saml", "scim"}},
		{name: "domain verification", in: []string{"Domain_Verification"}, want: []string{"domain_verification"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeCapabilities(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeCapabilities(%v) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCapabilities(%v) unexpected error: %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeCapabilities(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeCapabilities(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestLinkTTL checks that a link lasts as long as asked, an hour when nothing
// is asked, and that a lifetime out of range is refused rather than changed.
func TestLinkTTL(t *testing.T) {
	cases := []struct {
		name    string
		in      time.Duration
		want    time.Duration
		refused bool
	}{
		{name: "none asked defaults", in: 0, want: defaultTTL},
		{name: "the bounds themselves", in: minTTL, want: minTTL},
		{name: "the upper bound", in: maxTTL, want: maxTTL},
		{name: "within range", in: 2 * time.Hour, want: 2 * time.Hour},
		{name: "negative", in: -time.Hour, refused: true},
		{name: "below the minimum", in: time.Minute, refused: true},
		{name: "a week", in: 7 * 24 * time.Hour, refused: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := linkTTL(tc.in)
			if tc.refused {
				var e *errs.Error
				if !errors.As(err, &e) || e.Code != errs.CodeAdminPortalTTLOutOfRange || e.Metadata["max_seconds"] != 86400 {
					t.Fatalf("linkTTL(%v) = %v, %v; want refused with the bounds", tc.in, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("linkTTL(%v) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestLinkHas(t *testing.T) {
	l := Link{Capabilities: []string{"saml"}}
	if !l.Has("saml") {
		t.Error("Has(saml) = false, want true")
	}
	if l.Has("scim") {
		t.Error("Has(scim) = true, want false")
	}
}

func TestPortalSessionCookieSecurityAttributes(t *testing.T) {
	handler := &Handler{CookieSecure: true}
	recorder := httptest.NewRecorder()
	expiresAt := time.Now().Add(20 * time.Minute)
	handler.setSessionCookie(recorder, "opaque-session", expiresAt)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("portal cookie security attributes: %+v", cookie)
	}
	if cookie.Path != portalCookiePath || cookie.MaxAge <= 0 || cookie.MaxAge > 20*60 {
		t.Fatalf("portal cookie scope/lifetime: %+v", cookie)
	}
}
