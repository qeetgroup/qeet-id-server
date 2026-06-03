package tracing

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// Middleware instruments HTTP handlers with OpenTelemetry, starting (or
// continuing, via the configured propagators) a server span per request.
//
// When tracing is disabled (no endpoint configured) the global tracer is a
// no-op, so this is effectively free and always safe to mount.
//
// Span names use the matched chi route pattern (e.g. "GET /v1/users/{id}")
// rather than the raw path, keeping span cardinality bounded — mirroring how
// the metrics middleware labels by route. Because chi only resolves the
// pattern after routing, otelhttp starts with the method as the span name and
// we refine it once the route is known.
func Middleware(next http.Handler) http.Handler {
	instrumented := otelhttp.NewHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)

			if rc := chi.RouteContext(r.Context()); rc != nil {
				if pattern := rc.RoutePattern(); pattern != "" {
					trace.SpanFromContext(r.Context()).SetName(r.Method + " " + pattern)
				}
			}
		}),
		// Operation seeds the initial span name; the chi route pattern refines
		// it above once routing has matched.
		"http.request",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method
		}),
	)
	return instrumented
}
