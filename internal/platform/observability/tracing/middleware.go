package tracing

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

// Middleware starts or continues a server span per request. Spans are named by
// method and chi route pattern (e.g. "GET /v1/users/{id}"), not the raw path,
// to bound cardinality; the name is set once routing has matched. With tracing
// disabled it costs next to nothing.
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
