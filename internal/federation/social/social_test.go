package social

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
)

func TestNewService_TrimsTrailingSlash(t *testing.T) {
	// appBaseURL is used to build the SPA callback redirect; a trailing slash
	// would yield a double-slash path, so it must be trimmed.
	s := newTestService(t, new(pgxpool.Pool), new(auth.Service), func(d *Deps) { d.AppBaseURL = "https://app.qeet.com/" })
	if s.appBaseURL != "https://app.qeet.com" {
		t.Errorf("appBaseURL = %q, want trailing slash trimmed", s.appBaseURL)
	}
}

// TestValidateReturnTo checks that return_to accepts only "", a path with a
// single leading "/", and URLs on an allowed origin.
func TestValidateReturnTo(t *testing.T) {
	s := newTestService(t, new(pgxpool.Pool), new(auth.Service), func(d *Deps) {
		d.ReturnOrigins = []string{"https://login.qeet.in", "https://console.qeet.in/"}
	})

	for _, c := range []struct {
		name     string
		returnTo string
		ok       bool
	}{
		{"empty", "", true},
		{"path", "/oauth/authorize?client_id=abc&scope=openid+email", true},
		{"root", "/", true},
		{"encoded query", "/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcb", true},
		{"allowed origin", "https://login.qeet.in/oauth/authorize", true},
		{"allowed origin, upper case", "https://LOGIN.QEET.IN/oauth/authorize", true},
		{"allowed origin, root", "https://console.qeet.in/", true},

		{"other origin", "https://other.example/", false},
		{"other scheme", "http://login.qeet.in/oauth/authorize", false},
		{"longer host", "https://login.qeet.in.other.example/", false},
		{"other origin with allowed query", "https://other.example/?next=https://login.qeet.in", false},
		{"userinfo on allowed origin", "https://user@login.qeet.in/", false},
		{"userinfo host", "https://login.qeet.in@other.example/", false},
		{"no host", "javascript:alert(1)", false},
		{"opaque", "https:login.qeet.in/x", false},
		{"relative without slash", "oauth/authorize", false},
		{"double slash", "//other.example/path", false},
		{"slash backslash", `/\other.example/path`, false},
		{"backslash later", `/a\b`, false},
		{"tab after slash", "/\t/other.example/path", false},
		{"newline after slash", "/\n/other.example/path", false},
		{"carriage return after slash", "/\r/other.example/path", false},
		{"leading space", " //other.example/path", false},
		{"leading tab", "\t//other.example/path", false},
		{"space in path", "/a b", false},
		{"trailing newline", "/oauth/authorize\n", false},
		{"nul", "/a\x00b", false},
		{"delete", "/a\x7fb", false},
		{"C1 control", "/a\u0085b", false},
		{"no-break space", "/ /other.example", false},
		{"ideographic space", "/　/other.example", false},
		{"invalid utf-8", "/a\xffb", false},
		{"tab in allowed origin", "https://login.qeet.in/\t/x", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := s.validateReturnTo(c.returnTo)
			if c.ok && err != nil {
				t.Errorf("validateReturnTo(%q) = %v, want nil", c.returnTo, err)
			}
			if !c.ok && err == nil {
				t.Errorf("validateReturnTo(%q) = nil, want rejection", c.returnTo)
			}
		})
	}
}

// TestValidateReturnToWithNoAllowlist pins the safe default: with no origins
// configured, only root-relative paths are accepted.
func TestValidateReturnToWithNoAllowlist(t *testing.T) {
	s := newTestService(t, new(pgxpool.Pool), new(auth.Service))
	if err := s.validateReturnTo("/oauth/authorize"); err != nil {
		t.Errorf("root-relative path = %v, want nil", err)
	}
	if err := s.validateReturnTo("https://login.qeet.in/"); err == nil {
		t.Error("absolute URL with no allowlist = nil, want rejection")
	}
}
