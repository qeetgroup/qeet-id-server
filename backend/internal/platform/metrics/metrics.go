// Package metrics exposes Prometheus instrumentation: an HTTP middleware that
// records request count + latency (labelled by the chi route pattern, not the
// raw path, to keep cardinality bounded) and a /metrics handler. The default
// registry also exposes Go runtime + process metrics.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reqTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total HTTP requests, by method, route and status.",
	}, []string{"method", "route", "status"})

	reqDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency, by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_info",
		Help: "Build metadata; constant 1 carrying version/commit/goversion labels.",
	}, []string{"version", "commit", "goversion"})
)

// SetBuildInfo publishes the running binary's build metadata as a constant
// gauge (value 1) so dashboards and alerts can pivot on the deployed version.
func SetBuildInfo(version, commit, goversion string) {
	buildInfo.WithLabelValues(version, commit, goversion).Set(1)
}

// Middleware records request count + latency. Mount it high in the chain; the
// route label is read after the handler runs, so it reflects the matched chi
// pattern (e.g. "/v1/users/{id}") rather than the high-cardinality raw path.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK // handler wrote body without an explicit WriteHeader
		}
		reqDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		reqTotal.WithLabelValues(r.Method, route, strconv.Itoa(status)).Inc()
	})
}

// Handler serves the Prometheus exposition format for scraping. Restrict it to
// the scrape network in production (it's mounted at /metrics).
func Handler() http.Handler { return promhttp.Handler() }
