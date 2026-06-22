// Package ratelimit ships a token-bucket limiter keyed by string, used for
// in-process protection of unauth endpoints (login, magic link) and per-tenant
// / per-user / per-api-key throttling on authenticated endpoints.
//
// The bucket math lives behind a Store: the default in-memory store is
// per-process; a Redis store (redis.go) shares limits across replicas so a
// horizontally-scaled deployment enforces one global limit.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// Store is the token-bucket backend.
type Store interface {
	// Take attempts to consume one token for key (rate tokens/sec, burst
	// capacity). Returns whether it was allowed and, if not, the integer
	// seconds until a token frees up.
	Take(ctx context.Context, key string, rate, capacity float64) (allowed bool, retryAfter int, err error)
}

type bucket struct {
	tokens float64
	last   time.Time
}

type memStore struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newMemStore() *memStore { return &memStore{buckets: make(map[string]*bucket)} }

func (s *memStore) Take(_ context.Context, key string, rate, capacity float64) (bool, int, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		s.buckets[key] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * rate
		if b.tokens > capacity {
			b.tokens = capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false, retryAfterSecs(b.tokens, rate), nil
	}
	b.tokens--
	return true, 0, nil
}

// retryAfterSecs is the integer seconds until `tokens` reaches 1 at `rate`,
// minimum 1.
func retryAfterSecs(tokens, rate float64) int {
	secs := (1 - tokens) / rate
	if secs < 1 {
		return 1
	}
	return int(secs + 0.999)
}

type Limiter struct {
	store    Store
	rate     float64
	capacity float64
}

// New builds an in-process limiter: rate tokens/sec with the given burst capacity.
func New(rate float64, capacity int) *Limiter {
	return &Limiter{store: newMemStore(), rate: rate, capacity: float64(capacity)}
}

// NewWithStore builds a limiter over a shared store (e.g. Redis) so the limit
// holds across replicas.
func NewWithStore(store Store, rate float64, capacity int) *Limiter {
	return &Limiter{store: store, rate: rate, capacity: float64(capacity)}
}

// Take consumes one token for key, returning (allowed, retryAfterSeconds). It
// fails open (allowed) when the store errors, so an infra blip never
// hard-blocks traffic.
func (l *Limiter) Take(ctx context.Context, key string) (bool, int) {
	allowed, retry, err := l.store.Take(ctx, key, l.rate, l.capacity)
	if err != nil {
		return true, 0
	}
	return allowed, retry
}

// KeyFunc extracts a bucket key from a request. Returning the empty string
// disables rate limiting for that request — useful when the desired identifier
// is not present (e.g. PerTenant on a pre-auth endpoint).
type KeyFunc func(r *http.Request) string

// MiddlewareBy applies the limiter using a custom key extractor. scopeName is
// prefixed to the key so one Limiter/Store can host buckets for multiple scopes
// ("ip:1.2.3.4" never collides with "tenant:1.2.3.4"). On rejection it returns
// 429 with Retry-After.
func (l *Limiter) MiddlewareBy(scopeName string, extract KeyFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := extract(r)
			if id == "" {
				next.ServeHTTP(w, r)
				return
			}
			allowed, retry := l.Take(r.Context(), scopeName+":"+id)
			if !allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Middleware applies the limiter using client IP as the bucket key.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return l.MiddlewareBy("ip", PerIP)(next)
}

// PerIP keys requests by client IP.
func PerIP(r *http.Request) string {
	return httpx.ClientIP(r)
}

// PerTenant keys requests by the principal's tenant ID. Empty when unauthenticated.
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

// PerAPIKey keys requests by the API key ID when the principal was authenticated
// via API key (ActorType == "api_key"); empty otherwise.
func PerAPIKey(r *http.Request) string {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.ActorType != "api_key" {
		return ""
	}
	return p.Subject
}
