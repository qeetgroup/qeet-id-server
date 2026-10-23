package recovery

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
