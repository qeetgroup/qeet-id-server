package ratelimit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

var ctx = context.Background()

func TestTake_BurstThenRefill(t *testing.T) {
	l := New(10, 3) // 10 tok/s, burst 3
	for i := 0; i < 3; i++ {
		if ok, _ := l.Take(ctx, "k"); !ok {
			t.Fatalf("first %d requests must be allowed (burst=3); failed at %d", i+1, i)
		}
	}
	if ok, _ := l.Take(ctx, "k"); ok {
		t.Fatal("4th immediate request must be denied")
	}
}

func TestTake_DifferentKeysIndependent(t *testing.T) {
	l := New(1, 1)
	if ok, _ := l.Take(ctx, "a"); !ok {
		t.Fatal("a should be allowed")
	}
	if ok, _ := l.Take(ctx, "b"); !ok {
		t.Fatal("b should be allowed even after a (independent buckets)")
	}
	if ok, _ := l.Take(ctx, "a"); ok {
		t.Fatal("a's second request must be denied")
	}
}

func TestTake_RetryAfterZeroWhenAllowed(t *testing.T) {
	l := New(1, 5)
	if ok, retry := l.Take(ctx, "k"); !ok || retry != 0 {
		t.Errorf("allowed take: ok=%v retry=%d, want true/0", ok, retry)
	}
}

func TestTake_RetryAfterPositiveWhenEmpty(t *testing.T) {
	l := New(1, 1)
	l.Take(ctx, "k") // drain
	if ok, retry := l.Take(ctx, "k"); ok || retry < 1 {
		t.Errorf("empty take: ok=%v retry=%d, want false/>=1", ok, retry)
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

// TestMiddlewareBy_429CarriesErrorEnvelope checks that a 429 carries the
// standard error envelope with retry_after metadata and a Retry-After header.
func TestMiddlewareBy_429CarriesErrorEnvelope(t *testing.T) {
	l := New(1, 1)
	h := l.MiddlewareBy("ip", func(*http.Request) string { return "5.6.7.8" })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
	)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(httptest.NewRecorder(), req) // drain the single token

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}

	var body struct {
		Error struct {
			Code      string         `json:"code"`
			Message   string         `json:"message"`
			Retryable bool           `json:"retryable"`
			Metadata  map[string]any `json:"metadata"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not the error envelope (%q): %v", rec.Body.String(), err)
	}
	if body.Error.Code != errs.CodeTooManyRequests {
		t.Errorf("code = %q, want %q", body.Error.Code, errs.CodeTooManyRequests)
	}
	if body.Error.Message == "" {
		t.Error("429 envelope must carry a user-facing message")
	}
	if !body.Error.Retryable {
		t.Error("a throttled request is retryable")
	}
	if _, ok := body.Error.Metadata["retry_after"]; !ok {
		t.Error("retry_after should be exposed in metadata")
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After header must survive the envelope change")
	}
}

// TestPerIP_IgnoresXForwardedForWithoutTrustedProxy checks that PerIP ignores
// X-Forwarded-For when no proxy is trusted: the header is caller-supplied, so
// honouring it would give every spoofed value a fresh login bucket.
func TestPerIP_IgnoresXForwardedForWithoutTrustedProxy(t *testing.T) {
	httpx.SetTrustedProxyHops(0)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:34567"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := PerIP(req); got != "203.0.113.7" {
		t.Errorf("PerIP = %q, want the transport peer 203.0.113.7 (spoofed XFF must be ignored)", got)
	}
}

// TestPerIP_SpoofedXForwardedForCannotSplitBuckets checks that, behind one
// trusted proxy, forging the left of the chain still lands in one bucket.
func TestPerIP_SpoofedXForwardedForCannotSplitBuckets(t *testing.T) {
	httpx.SetTrustedProxyHops(1)
	t.Cleanup(func() { httpx.SetTrustedProxyHops(0) })

	seen := map[string]struct{}{}
	for _, forged := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234" // the proxy
		// What the origin sees when a caller sends "X-Forwarded-For: <forged>"
		// and the proxy appends the address it actually accepted from.
		req.Header.Set("X-Forwarded-For", forged+", 203.0.113.7")
		seen[PerIP(req)] = struct{}{}
	}
	if len(seen) != 1 {
		t.Fatalf("forged X-Forwarded-For produced %d distinct buckets, want 1: %v", len(seen), seen)
	}
	if _, ok := seen["203.0.113.7"]; !ok {
		t.Errorf("bucket key = %v, want the proxy-observed peer 203.0.113.7", seen)
	}
}

// TestPerIP_TrustedProxyReadsRealClient covers the normal, unforged case.
func TestPerIP_TrustedProxyReadsRealClient(t *testing.T) {
	httpx.SetTrustedProxyHops(1)
	t.Cleanup(func() { httpx.SetTrustedProxyHops(0) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	if got := PerIP(req); got != "198.51.100.4" {
		t.Errorf("PerIP = %q, want 198.51.100.4", got)
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
		name string
		p    *httpx.Principal
		want string
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
