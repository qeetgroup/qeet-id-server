package httpx

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestSecurityHeaders_AllHeadersSet(t *testing.T) {
	h := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	want := map[string]string{
		"Strict-Transport-Security":         "max-age=31536000; includeSubDomains",
		"X-Frame-Options":                   "DENY",
		"X-Content-Type-Options":            "nosniff",
		"Referrer-Policy":                   "strict-origin-when-cross-origin",
		"Content-Security-Policy":           "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"Cross-Origin-Resource-Policy":      "cross-origin",
		"X-DNS-Prefetch-Control":            "off",
		"X-Permitted-Cross-Domain-Policies": "none",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if rec.Header().Get("Permissions-Policy") == "" {
		t.Error("Permissions-Policy header missing")
	}
}

func TestSecurityHeaders_HSTSDisabledInDev(t *testing.T) {
	h := SecurityHeaders(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS should be absent when disabled, got %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("other headers should still apply, X-Frame-Options = %q", got)
	}
}

func TestSecurityHeaders_PermissionsPolicyLeavesWebAuthnAllowed(t *testing.T) {
	h := SecurityHeaders(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	pp := rec.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Fatal("Permissions-Policy header missing")
	}
	for _, banned := range []string{"publickey-credentials-get", "publickey-credentials-create"} {
		if strings.Contains(pp, banned) {
			t.Errorf("Permissions-Policy must not disable %s (would break WebAuthn): %s", banned, pp)
		}
	}
}

func TestInFlight_CountsActiveRequests(t *testing.T) {
	in := NewInFlight()
	if got := in.Count(); got != 0 {
		t.Errorf("initial Count = %d, want 0", got)
	}

	enter := make(chan struct{})
	release := make(chan struct{})
	h := in.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(enter)
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	done := make(chan struct{})
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		close(done)
	}()

	<-enter
	if got := in.Count(); got != 1 {
		t.Errorf("during handler Count = %d, want 1", got)
	}
	close(release)
	<-done
	if got := in.Count(); got != 0 {
		t.Errorf("after handler Count = %d, want 0", got)
	}
}

func TestInFlight_DecrementsOnPanic(t *testing.T) {
	in := NewInFlight()
	h := in.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	defer func() {
		_ = recover()
		if got := in.Count(); got != 0 {
			t.Errorf("after panic Count = %d, want 0 (defer must run)", got)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestInFlight_ConcurrentRequests(t *testing.T) {
	in := NewInFlight()
	const N = 50
	enter := make(chan struct{}, N)
	release := make(chan struct{})
	h := in.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enter <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < N; i++ {
		go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	for i := 0; i < N; i++ {
		<-enter
	}
	if got := in.Count(); got != N {
		t.Errorf("with %d concurrent requests Count = %d", N, got)
	}
	close(release)
}

func TestClientIP_TrustedProxyHops(t *testing.T) {
	tests := []struct {
		name       string
		hops       int
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no trusted proxy ignores a forged header",
			hops:       0,
			remoteAddr: "203.0.113.7:4444",
			xff:        "9.9.9.9",
			want:       "203.0.113.7",
		},
		{
			name:       "one proxy, no forgery",
			hops:       1,
			remoteAddr: "10.0.0.1:80",
			xff:        "198.51.100.4",
			want:       "198.51.100.4",
		},
		{
			name:       "one proxy, caller prepended a forged hop",
			hops:       1,
			remoteAddr: "10.0.0.1:80",
			xff:        "9.9.9.9, 198.51.100.4",
			want:       "198.51.100.4",
		},
		{
			name:       "one proxy, caller prepended a whole forged chain",
			hops:       1,
			remoteAddr: "10.0.0.1:80",
			xff:        "1.1.1.1, 2.2.2.2, 3.3.3.3, 198.51.100.4",
			want:       "198.51.100.4",
		},
		{
			name:       "two proxies",
			hops:       2,
			remoteAddr: "10.0.0.1:80",
			xff:        "198.51.100.4, 10.0.0.9",
			want:       "198.51.100.4",
		},
		{
			name:       "chain shorter than declared falls back to the peer",
			hops:       2,
			remoteAddr: "203.0.113.7:4444",
			xff:        "9.9.9.9",
			want:       "203.0.113.7",
		},
		{
			name:       "X-Real-IP is never trusted",
			hops:       1,
			remoteAddr: "203.0.113.7:4444",
			xff:        "",
			want:       "203.0.113.7",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			SetTrustedProxyHops(tc.hops)
			t.Cleanup(func() { SetTrustedProxyHops(0) })
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			r.Header.Set("X-Real-IP", "6.6.6.6")
			if got := ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestClientIP_ReadsEveryForwardedLine checks that a proxy appending its own
// X-Forwarded-For line, rather than extending the caller's, still has the
// client read from its entry, not the caller's forged one.
func TestClientIP_ReadsEveryForwardedLine(t *testing.T) {
	SetTrustedProxyHops(1)
	t.Cleanup(func() { SetTrustedProxyHops(0) })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:80"
	r.Header.Add("X-Forwarded-For", "9.9.9.9")
	r.Header.Add("X-Forwarded-For", "198.51.100.4")
	if got := ClientIP(r); got != "198.51.100.4" {
		t.Errorf("ClientIP = %q, want the proxy's entry 198.51.100.4", got)
	}
}

// TestSourceNetwork checks that an IPv4 address is its own network and an
// IPv6 one is its /64.
func TestSourceNetwork(t *testing.T) {
	for ip, want := range map[string]string{
		"203.0.113.7":                    "203.0.113.7",
		" 203.0.113.7 ":                  "203.0.113.7",
		"::ffff:203.0.113.7":             "203.0.113.7", // IPv4-mapped is the IPv4 source
		"2001:db8:1:2:aaaa:bbbb:cccc:d":  "2001:db8:1:2::/64",
		"2001:db8:1:2::9":                "2001:db8:1:2::/64", // same /64: same network
		"2001:db8:1:3::9":                "2001:db8:1:3::/64",
		"fe80::1%eth0":                   "fe80::/64",
		"":                               "",
		"not-an-address":                 "",
		"203.0.113.7:4000":               "",
		"2001:db8:1:2:aaaa:bbbb:cccc:dd": "2001:db8:1:2::/64",
	} {
		if got := SourceNetwork(ip); got != want {
			t.Errorf("SourceNetwork(%q) = %q, want %q", ip, got, want)
		}
	}
}

// TestRefuseEncodedSeparators checks that a path with an encoded slash or
// backslash, in either case, is refused before the handler, while other
// encodings and a query carrying encoded slashes pass.
func TestRefuseEncodedSeparators(t *testing.T) {
	h := RefuseEncodedSeparators(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for target, want := range map[string]int{
		"/v1/users/a%2Fb":       http.StatusBadRequest,
		"/v1/users/a%2fb/roles": http.StatusBadRequest,
		"/v1/users/a%5Cb":       http.StatusBadRequest,
		"/v1/users/a%5cb":       http.StatusBadRequest,
		"/v1/users/a%252Fb":     http.StatusNoContent,
		"/v1/users/a%20b":       http.StatusNoContent,
		"/v1/oauth/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcb": http.StatusNoContent,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", target, rec.Code, want)
		}
	}
}

// TestAccessLogNamesThePrincipal checks that the access line carries the
// principal an authentication middleware below it adds to the request.
func TestAccessLogNamesThePrincipal(t *testing.T) {
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	userID, organizationID := uuid.New(), uuid.New()
	router := chi.NewRouter()
	router.Use(AccessLog)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &Principal{UserID: &userID, OrganizationID: &organizationID, ActorType: "user"}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	})
	router.Get("/v1/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil))

	for _, want := range []string{`"user_id":"` + userID.String() + `"`, `"organization_id":"` + organizationID.String() + `"`, `"actor_type":"user"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("access log lacks %s: %s", want, logs.String())
		}
	}
}

func TestAccessAndErrorLogsRedactAdminPortalToken(t *testing.T) {
	const secret = "portal-capability-token-must-not-leak"
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	router := chi.NewRouter()
	router.Use(AccessLog)
	router.Get("/v1/admin-portal/{token}/context", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, r, errors.New("forced failure"))
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/admin-portal/"+secret+"/context", nil))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("matched-route logs leaked portal token: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `/v1/admin-portal/{token}/context`) {
		t.Fatalf("logs should retain the safe route pattern: %s", logs.String())
	}

	logs.Reset()
	request := httptest.NewRequest(http.MethodGet, "/v1/admin-portal/"+secret+"/context", nil)
	WriteError(httptest.NewRecorder(), request, errors.New("forced unmatched failure"))
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("unmatched-route error log leaked portal token: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "/v1/admin-portal/{redacted}/context") {
		t.Fatalf("unmatched route should redact the capability segment: %s", logs.String())
	}
}
