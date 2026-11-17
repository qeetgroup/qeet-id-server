// Package ratelimit provides string-keyed token-bucket limiters: per IP before
// sign-in, and per organization, user or API key after. The default Store is in
// process; NewRedisStore shares buckets across replicas.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	rate   float64 // tokens/sec, so a sweep knows when it has refilled
	full   float64 // capacity
}

// refilledBy reports whether b holds its capacity again at now, so it is the
// same as no bucket.
func (b *bucket) refilledBy(now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*b.rate >= b.full
}

// The in-process store drops buckets that have refilled, at most once a
// sweepInterval, and holds at most maxBuckets, so keys a caller chooses can't
// grow it without bound.
const (
	sweepInterval = time.Minute
	maxBuckets    = 100_000
)

type memStore struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

func newMemStore() *memStore { return &memStore{buckets: make(map[string]*bucket)} }

// sweep drops refilled buckets once a sweepInterval and, at maxBuckets, an
// arbitrary one to make room. Dropping one only forgets what it spent, as a
// store error would. The caller holds mu.
func (s *memStore) sweep(now time.Time) {
	if now.Sub(s.lastSweep) >= sweepInterval {
		s.lastSweep = now
		for k, b := range s.buckets {
			if b.refilledBy(now) {
				delete(s.buckets, k)
			}
		}
	}
	for k := range s.buckets {
		if len(s.buckets) < maxBuckets {
			break
		}
		delete(s.buckets, k)
	}
}

// NewMemStore returns a new in-process token-bucket store.
func NewMemStore() Store { return newMemStore() }

func (s *memStore) Take(_ context.Context, key string, rate, capacity float64) (bool, int, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		s.sweep(now)
		b = &bucket{tokens: capacity, last: now, rate: rate, full: capacity}
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

// Limiter is a token-bucket rate limiter over a Store. It is safe for
// concurrent use.
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
// is not present (e.g. PerOrganization on a pre-auth endpoint).
type KeyFunc func(r *http.Request) string

// MiddlewareBy applies the limiter using a custom key extractor. scopeName is
// prefixed to the key so one Limiter/Store can host buckets for multiple scopes
// ("ip:1.2.3.4" never collides with "organization:1.2.3.4"). On rejection it returns
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
				// Write the standard error envelope, not a bare status, so clients get a
				// code to branch on.
				httpx.WriteError(w, r, errs.ErrTooManyRequests.WithMetadata(
					map[string]any{"retry_after": retry}))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Middleware applies the limiter per client IP under the scope "ip". Limiters
// sharing a Store need scopes of their own: use MiddlewareBy.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return l.MiddlewareBy("ip", PerIP)(next)
}

// PerIP keys requests by the client's network: its IPv4 address, or the /64
// of its IPv6 one, so rotating addresses inside one allocation shares a
// bucket.
func PerIP(r *http.Request) string {
	ip := httpx.ClientIP(r)
	if network := httpx.SourceNetwork(ip); network != "" {
		return network
	}
	return ip
}

// PerOrganization keys requests by the principal's organization ID. Empty when unauthenticated.
func PerOrganization(r *http.Request) string {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.OrganizationID == nil {
		return ""
	}
	return p.OrganizationID.String()
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
