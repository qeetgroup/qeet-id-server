package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
		"Content-Security-Policy":           "default-src 'none'; frame-ancestors 'none'",
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
		if contains(pp, banned) {
			t.Errorf("Permissions-Policy must not disable %s (would break WebAuthn): %s", banned, pp)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
