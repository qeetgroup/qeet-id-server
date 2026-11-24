package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestCORSPolicy checks who may read which responses from another origin: the
// operator's origins with credentials anywhere, sending the headers they are
// given; the public paths any origin, without credentials; the application
// paths, an origin an application allows, without credentials, and nothing
// else for that origin; and nothing for an origin nobody allows.
func TestCORSPolicy(t *testing.T) {
	const console, spa, stranger = "https://console.example.test", "https://spa.example.test", "https://evil.example.test"
	policy := httpx.CORS(httpx.CORSConfig{
		Operator:    []string{console},
		Headers:     []string{"Idempotency-Key"},
		PublicPaths: []string{"/.well-known/openid-configuration", "/.well-known/jwks.json"},
		AppPaths:    []string{"/v1/oauth/token", "/v1/oauth/userinfo", "/oauth/revoke"},
		AppOrigin:   func(_ context.Context, origin string) bool { return origin == spa },
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	ask := func(method, path, origin string) http.Header {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Origin", origin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}
		rec := httptest.NewRecorder()
		policy.ServeHTTP(rec, req)
		return rec.Header()
	}
	for _, tc := range []struct {
		name, method, path, origin string
		allowOrigin, credentials   string
	}{
		{"the console on an API route", http.MethodGet, "/v1/users", console, console, "true"},
		{"the console on userinfo", http.MethodGet, "/v1/oauth/userinfo", console, console, "true"},
		{"an application's origin asking the token endpoint", http.MethodOptions, "/v1/oauth/token", spa, spa, ""},
		{"an application's origin on userinfo", http.MethodGet, "/v1/oauth/userinfo", spa, spa, ""},
		{"an application's origin on revocation", http.MethodOptions, "/oauth/revoke", spa, spa, ""},
		{"an application's origin on an API route", http.MethodGet, "/v1/users", spa, "", ""},
		{"an unknown origin asking the token endpoint", http.MethodOptions, "/v1/oauth/token", stranger, "", ""},
		{"an unknown origin reading the signing keys", http.MethodGet, "/.well-known/jwks.json", stranger, "*", ""},
		{"an unknown origin reading discovery", http.MethodGet, "/.well-known/openid-configuration", stranger, "*", ""},
	} {
		h := ask(tc.method, tc.path, tc.origin)
		if got := h.Get("Access-Control-Allow-Origin"); got != tc.allowOrigin {
			t.Errorf("%s: Access-Control-Allow-Origin %q, want %q", tc.name, got, tc.allowOrigin)
		}
		if got := h.Get("Access-Control-Allow-Credentials"); got != tc.credentials {
			t.Errorf("%s: Access-Control-Allow-Credentials %q, want %q", tc.name, got, tc.credentials)
		}
	}

	req := httptest.NewRequest(http.MethodOptions, "/v1/users", nil)
	req.Header.Set("Origin", console)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "Idempotency-Key, X-CSRF-Token")
	rec := httptest.NewRecorder()
	policy.ServeHTTP(rec, req)
	if got := strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers")); !strings.Contains(got, "idempotency-key") || !strings.Contains(got, "x-csrf-token") {
		t.Errorf("the console's preflight for its own and the given headers: Access-Control-Allow-Headers %q", got)
	}
}
