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
