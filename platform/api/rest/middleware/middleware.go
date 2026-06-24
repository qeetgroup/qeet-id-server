package httpx

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// InFlight tracks the number of HTTP requests currently being processed.
// Used during graceful shutdown to report (and bound) the number of
// requests still in flight when the server begins draining.
type InFlight struct {
	n atomic.Int64
}

func NewInFlight() *InFlight { return &InFlight{} }

// Count returns the number of in-flight requests at the call site. Safe
// for concurrent use.
func (i *InFlight) Count() int64 { return i.n.Load() }

// Middleware increments the in-flight counter on entry and decrements on
// exit, even when the handler panics (the deferred decrement runs before
// Recoverer's recover() catches the panic in the caller's frame, so
// place this middleware INSIDE Recoverer in the chain to keep counts
// accurate when handlers panic).
func (i *InFlight) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.n.Add(1)
		defer i.n.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// AccessLog emits one structured line per request after it completes.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		slog.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"dur_ms", time.Since(start).Milliseconds(),
			"req_id", RequestID(r),
		)
	})
}

// permissionsPolicy disables browser features the identity API has no need to
// expose. publickey-credentials-{get,create} are intentionally omitted so
// frontends served from the same registrable domain can run WebAuthn passkey
// ceremonies.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), " +
	"cross-origin-isolated=(), display-capture=(), encrypted-media=(), " +
	"fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), " +
	"magnetometer=(), microphone=(), midi=(), payment=(), " +
	"picture-in-picture=(), screen-wake-lock=(), sync-xhr=(), usb=(), " +
	"web-share=(), xr-spatial-tracking=()"

// SecurityHeaders returns a middleware that applies standard hardening
// headers to every response. enableHSTS controls whether
// Strict-Transport-Security is emitted; it should be off in dev so localhost
// HTTP doesn't get locked into HTTPS-only by the browser.
func SecurityHeaders(enableHSTS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if enableHSTS {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "cross-origin")
			h.Set("Permissions-Policy", permissionsPolicy)
			h.Set("X-DNS-Prefetch-Control", "off")
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			next.ServeHTTP(w, r)
		})
	}
}
