package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
)

// TestHealthAnswersWhileTheHasherIsFull checks that the health probes never
// wait behind password hashing: with every hashing slot and queue place taken,
// /healthz and /readyz still answer at once.
func TestHealthAnswersWhileTheHasherIsFull(t *testing.T) {
	router := NewRouter(routeInventoryDeps(t))
	password.Configure(password.Limits{Concurrency: 1, Queue: 1, MaxWait: time.Minute})
	t.Cleanup(func() { password.Configure(password.Limits{}) })
	release := password.FillForTest()
	defer release()
	for _, path := range []string{"/healthz", "/readyz"} {
		start := time.Now()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s with the hasher full: %d %s, want 200", path, rec.Code, rec.Body.String())
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("GET %s with the hasher full took %v, want at once", path, elapsed)
		}
	}
}
