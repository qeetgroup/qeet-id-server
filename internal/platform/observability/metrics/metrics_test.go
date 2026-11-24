package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestMiddlewareAndHandler(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/v1/ping/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Handle("/metrics", Handler())
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Drive a request so the counters move.
	resp, err := http.Get(srv.URL + "/v1/ping/123")
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	for _, want := range []string{
		"http_requests_total",
		"http_request_duration_seconds",
		`route="/v1/ping/{id}"`, // the chi pattern, not the raw /v1/ping/123
		`status="204"`,
		"go_goroutines", // default Go collector is exposed too
	} {
		if !strings.Contains(s, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
}

// A client can send any word as the method, so made-up ones share one series: each adding its own
// would let anyone grow the metrics without limit.
func TestMadeUpMethodsShareOneSeries(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Middleware)
	r.Get("/v1/ping", func(http.ResponseWriter, *http.Request) {})
	for _, method := range []string{"BREW", "WHEN", http.MethodGet} {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, "/v1/ping", nil))
	}

	scrape := httptest.NewRecorder()
	Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	s := scrape.Body.String()
	for _, made := range []string{`method="BREW"`, `method="WHEN"`} {
		if strings.Contains(s, made) {
			t.Errorf("/metrics has a series of its own for %s", made)
		}
	}
	for _, want := range []string{`method="other"`, `method="GET"`} {
		if !strings.Contains(s, want) {
			t.Errorf("/metrics missing %s", want)
		}
	}
}
