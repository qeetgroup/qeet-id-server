package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestMetricsNeedTheirToken checks that /metrics answers only a scraper with
// its token, is open without one only in development, and is otherwise off.
func TestMetricsNeedTheirToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, tc := range []struct {
		name, token, header string
		open                bool
		want                int
	}{
		{"no token, development", "", "", true, http.StatusOK},
		{"no token, elsewhere", "", "Bearer anything", false, http.StatusNotFound},
		{"the token", "scrape-secret", "Bearer scrape-secret", false, http.StatusOK},
		{"another token", "scrape-secret", "Bearer guess", true, http.StatusNotFound},
		{"no header", "scrape-secret", "", true, http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		httpx.MetricsGuard(tc.token, tc.open, next).ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
