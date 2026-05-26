// Package ratelimit ships a simple token-bucket limiter keyed by string.
// Suitable for in-process protection of unauth endpoints (login, magic
// link) and for per-tenant / per-user / per-api-key throttling on
// authenticated endpoints. Swap for Redis when the monolith grows beyond
// one node.
package ratelimit

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type bucket struct {
	tokens   float64
	last     time.Time
	rate     float64 // tokens per second
	capacity float64
}

type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	capacity float64
}

func New(rate float64, capacity int) *Limiter {
	return &Limiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		capacity: float64(capacity),
	}
}

// Allow consumes one token for the bucket identified by key. Returns true
// when the request is allowed; false when the bucket is empty.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketLocked(key, now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfter returns the integer seconds until the bucket regenerates
// enough tokens for one more request. Returns 0 when the bucket already
// has at least one token available, 1 minimum otherwise.
func (l *Limiter) RetryAfter(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.bucketLocked(key, time.Now())
	if b.tokens >= 1 {
		return 0
	}
	secs := (1 - b.tokens) / b.rate
	if secs < 1 {
		return 1
	}
	return int(secs + 0.999)
}

// bucketLocked fetches or initialises a bucket and refills it based on
// elapsed time. Caller must hold l.mu.
func (l *Limiter) bucketLocked(key string, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, last: now, rate: l.rate, capacity: l.capacity}
		l.buckets[key] = b
		return b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	return b
}

// KeyFunc extracts a bucket key from a request. Returning the empty string
// disables rate limiting for that request — useful when the desired
// identifier is not present (e.g. PerTenant on a pre-auth endpoint).
type KeyFunc func(r *http.Request) string

// MiddlewareBy applies the limiter using a custom key extractor. The
// scopeName is prefixed to the key so the same Limiter can safely host
// buckets for multiple scopes ("ip:1.2.3.4" never collides with
// "tenant:1.2.3.4"). On rejection it returns 429 with Retry-After.
func (l *Limiter) MiddlewareBy(scopeName string, extract KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := extract(r)
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := scopeName + ":" + id
			if !l.Allow(key) {
				w.Header().Set("Retry-After", strconv.Itoa(l.RetryAfter(key)))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Middleware applies the limiter using client IP as the bucket key. Kept
// for backwards compatibility with existing callers; new code should
// prefer MiddlewareBy with an explicit scope name.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return l.MiddlewareBy("ip", PerIP)(next)
}

// PerIP keys requests by client IP.
func PerIP(r *http.Request) string {
	return httpx.ClientIP(r)
}

// PerTenant keys requests by the principal's tenant ID. Returns the empty
// string when the request is unauthenticated or has no tenant.
func PerTenant(r *http.Request) string {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		return ""
	}
	return p.TenantID.String()
}

// PerUser keys requests by the principal's user ID. Empty when missing.
func PerUser(r *http.Request) string {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		return ""
	}
	return p.UserID.String()
}

// PerAPIKey keys requests by the API key ID when the principal was
// authenticated via API key (ActorType == "api_key"); empty otherwise.
func PerAPIKey(r *http.Request) string {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.ActorType != "api_key" {
		return ""
	}
	return p.Subject
}
