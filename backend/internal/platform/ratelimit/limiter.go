// Package ratelimit ships a simple token-bucket limiter keyed by string.
// Suitable for in-process protection of unauth endpoints (login, magic
// link). Swap for Redis when the monolith grows beyond one node.
package ratelimit

import (
	"net/http"
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

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.capacity, last: now, rate: l.rate, capacity: l.capacity}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Middleware applies the limiter using client IP as the bucket key.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(httpx.ClientIP(r)) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
