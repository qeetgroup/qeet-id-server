package recovery

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMagicResendRefusesAnEmptyToken checks that resending with no token is refused as an invalid
// link before anything is looked up (the handler has no service here), not given the neutral answer.
func TestMagicResendRefusesAnEmptyToken(t *testing.T) {
	for _, body := range []string{`{}`, `{"token": ""}`, `{"token": "  "}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/magic-link/resend", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		(&Handler{}).magicResend(w, r)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "recovery.magic_link_invalid") {
			t.Errorf("%s: %d %s, want 400 recovery.magic_link_invalid", body, w.Code, w.Body.String())
		}
	}
}

func TestAuthorizeReturnTo(t *testing.T) {
	h := &Handler{PublicBaseURL: "https://api.id.qeet.in"}
	cases := []struct {
		name, raw, want string
	}{
		{"own authorize endpoint", "https://api.id.qeet.in/v1/oauth/authorize?client_id=rp", "https://api.id.qeet.in/v1/oauth/authorize?client_id=rp"},
		{"empty", "", ""},
		{"the Host the client sent", "https://evil.example/v1/oauth/authorize", ""},
		{"downgraded scheme", "http://api.id.qeet.in/v1/oauth/authorize", ""},
		{"userinfo host trick", "https://api.id.qeet.in@evil.example/v1/oauth/authorize", ""},
		{"other path", "https://api.id.qeet.in/v1/me", ""},
		{"relative", "/v1/oauth/authorize", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", nil)
			r.Host = "evil.example"
			if got := h.authorizeReturnTo(r, c.raw); got != c.want {
				t.Errorf("authorizeReturnTo(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}
