package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
)

// TestRequestIDHeaderEchoesTheRequestID checks that every response carries the
// request's ID in X-Request-Id: the one chi assigned, or the caller's own.
func TestRequestIDHeaderEchoesTheRequestID(t *testing.T) {
	var seen string
	h := middleware.RequestID(RequestIDHeader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestID(r)
		w.WriteHeader(http.StatusNoContent)
	})))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if got := rec.Header().Get("X-Request-Id"); got == "" || got != seen {
		t.Fatalf("X-Request-Id = %q, want the assigned ID %q", got, seen)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("X-Request-Id", "caller-42")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-Id"); got != "caller-42" {
		t.Fatalf("X-Request-Id = %q, want the caller's own ID", got)
	}
}
