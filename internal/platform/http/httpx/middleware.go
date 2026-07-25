package httpx

import (
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/trace"
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

// AccessLog emits one structured log record per request after the handler
// returns. Level: INFO for 1xx–3xx, WARN for 4xx, ERROR for 5xx.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		// Sub-millisecond precision: microseconds → float ms.
		durMS := float64(time.Since(start).Microseconds()) / 1000.0

		// Prefer chi route pattern ("/v1/users/{id}") over raw path to keep
		// log cardinality bounded — same as the metrics middleware.
		route := r.URL.Path
		if rc := chi.RouteContext(r.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				route = p
			}
		}

		attrs := make([]slog.Attr, 0, 16)
		attrs = append(attrs,
			slog.String("method", r.Method),
			slog.String("route", route),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int("bytes", ww.BytesWritten()),
			slog.Float64("dur_ms", durMS),
			slog.String("req_id", RequestID(r)),
			slog.String("proto", r.Proto),
			slog.String("host", r.Host),
			slog.String("client_ip", ClientIP(r)),
		)

		if ua := r.UserAgent(); ua != "" {
			attrs = append(attrs, slog.String("user_agent", ua))
		}

		// OTel trace/span IDs — enables log-to-trace correlation in Grafana / Loki.
		if span := trace.SpanFromContext(r.Context()); span.SpanContext().IsValid() {
			sc := span.SpanContext()
			attrs = append(attrs,
				slog.String("trace_id", sc.TraceID().String()),
				slog.String("span_id", sc.SpanID().String()),
			)
		}

		// Identity fields — present after auth middleware has run.
		if p := PrincipalFromCtx(r.Context()); p != nil {
			if p.TenantID != nil {
				attrs = append(attrs, slog.String("tenant_id", p.TenantID.String()))
			}
			if p.UserID != nil {
				attrs = append(attrs, slog.String("user_id", p.UserID.String()))
			}
			if p.ActorType != "" {
				attrs = append(attrs, slog.String("actor_type", p.ActorType))
			}
		}

		level := slog.LevelInfo
		switch {
		case status >= 500:
			level = slog.LevelError
		case status >= 400:
			level = slog.LevelWarn
		}
		slog.Default().LogAttrs(r.Context(), level, "http", attrs...)
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
