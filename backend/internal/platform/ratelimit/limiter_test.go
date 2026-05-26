package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

func TestAllow_BurstThenRefill(t *testing.T) {
	l := New(10, 3) // 10 tok/s, burst 3
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("first %d requests must be allowed (burst=3); failed at %d", i+1, i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th immediate request must be denied")
	}
}

func TestAllow_DifferentKeysIndependent(t *testing.T) {
	l := New(1, 1)
	if !l.Allow("a") {
		t.Fatal("a should be allowed")
	}
	if !l.Allow("b") {
		t.Fatal("b should be allowed even after a (independent buckets)")
	}
	if l.Allow("a") {
		t.Fatal("a's second request must be denied")
	}
}

func TestRetryAfter_ZeroWhenTokensAvailable(t *testing.T) {
	l := New(1, 5)
	if got := l.RetryAfter("k"); got != 0 {
		t.Errorf("RetryAfter with full bucket = %d, want 0", got)
	}
}

func TestRetryAfter_AtLeastOneWhenEmpty(t *testing.T) {
	l := New(1, 1)
	l.Allow("k") // drain
	if got := l.RetryAfter("k"); got < 1 {
		t.Errorf("RetryAfter on empty bucket = %d, want >=1", got)
	}
}

func TestMiddlewareBy_PassthroughOnEmptyKey(t *testing.T) {
	// Extractor that always returns "" must let every request through.
	l := New(0.0001, 1) // ridiculously low; first request would drain
	handlerCalls := 0
	h := l.MiddlewareBy("noop", func(*http.Request) string { return "" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalls++
			w.WriteHeader(http.StatusOK)
		}),
	)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("empty-key passthrough request %d: got %d, want 200", i, rec.Code)
		}
	}
	if handlerCalls != 5 {
		t.Errorf("handler invoked %d times, want 5", handlerCalls)
	}
}

func TestMiddlewareBy_ScopePrefixIsolatesBuckets(t *testing.T) {
	// Same id under different scope names must not collide.
	l := New(1, 1)
	h1 := l.MiddlewareBy("ip", func(*http.Request) string { return "1.2.3.4" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	h2 := l.MiddlewareBy("tenant", func(*http.Request) string { return "1.2.3.4" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h1.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first ip req = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, req) // different scope, same id — must be independent
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant scope must have its own bucket: got %d", rec.Code)
	}
}

func TestMiddlewareBy_429HasRetryAfter(t *testing.T) {
	l := New(1, 1)
	h := l.MiddlewareBy("ip", func(*http.Request) string { return "1.2.3.4" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request must succeed: %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second request must 429: got %d", rec.Code)
	}
	ra := rec.Header().Get("Retry-After")
	if ra == "" {
		t.Error("Retry-After header missing on 429")
	}
	if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Errorf("Retry-After = %q, want positive integer", ra)
	}
}

func TestPerIP_UsesXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := PerIP(req); got != "9.9.9.9" {
		t.Errorf("PerIP = %q, want 9.9.9.9", got)
	}
}

func TestPerTenant_EmptyWhenUnauthenticated(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := PerTenant(req); got != "" {
		t.Errorf("PerTenant with no principal = %q, want empty", got)
	}
}

func TestPerTenant_ReturnsTenantUUID(t *testing.T) {
	tid := uuid.New()
	p := &httpx.Principal{TenantID: &tid}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(httpx.WithPrincipal(httptest.NewRequest(http.MethodGet, "/", nil).Context(), p))
	if got := PerTenant(req); got != tid.String() {
		t.Errorf("PerTenant = %q, want %s", got, tid)
	}
}

func TestPerUser_ReturnsUserUUID(t *testing.T) {
	uid := uuid.New()
	p := &httpx.Principal{UserID: &uid}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(httpx.WithPrincipal(httptest.NewRequest(http.MethodGet, "/", nil).Context(), p))
	if got := PerUser(req); got != uid.String() {
		t.Errorf("PerUser = %q, want %s", got, uid)
	}
}

func TestPerAPIKey_OnlyForAPIKeyPrincipal(t *testing.T) {
	cases := []struct {
		name   string
		p      *httpx.Principal
		want   string
	}{
		{"nil_principal", nil, ""},
		{"user_principal", &httpx.Principal{ActorType: "user", Subject: "u_1"}, ""},
		{"api_key_principal", &httpx.Principal{ActorType: "api_key", Subject: "k_abc"}, "k_abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.p != nil {
				req = req.WithContext(httpx.WithPrincipal(req.Context(), tc.p))
			}
			if got := PerAPIKey(req); got != tc.want {
				t.Errorf("PerAPIKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMiddlewareBy_RefillOverTime(t *testing.T) {
	// rate=50/s burst=1 → after draining we should be able to make another
	// request ~20ms later. Use a coarse window to keep the test stable.
	l := New(50, 1)
	h := l.MiddlewareBy("ip", func(*http.Request) string { return "k" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first req = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second req = %d (want 429)", rec.Code)
	}

	time.Sleep(40 * time.Millisecond) // 2 tokens of headroom
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("after refill window, expected 200 got %d", rec.Code)
	}
}

func TestMiddleware_BackwardsCompat(t *testing.T) {
	// The exported Middleware shim must still work the same as before.
	l := New(1, 1)
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("first req = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second req = %d (want 429)", rec.Code)
	}
}
