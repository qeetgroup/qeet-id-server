package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newHandler() *Handler {
	return New("qeet-identity", "test", time.Now().Add(-5*time.Second))
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body: %v: %s", err, rec.Body.String())
	}
	return m
}

func TestLiveness_AlwaysOK(t *testing.T) {
	h := newHandler()
	// Even with a failing readiness check registered, liveness must still
	// return 200 — they probe different things.
	h.AddReadiness("anything", func(ctx context.Context) error {
		return errors.New("broken")
	})

	rec := httptest.NewRecorder()
	h.Liveness(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("Liveness status = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["service"] != "qeet-identity" {
		t.Errorf("service = %v", body["service"])
	}
}

func TestReadiness_OKWhenNoChecks(t *testing.T) {
	rec := httptest.NewRecorder()
	newHandler().Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["status"] != "ready" {
		t.Errorf("body = %v", body)
	}
}

func TestReadiness_OKWhenAllChecksPass(t *testing.T) {
	h := newHandler()
	h.AddReadiness("db", func(ctx context.Context) error { return nil })
	h.AddReadiness("outbox", func(ctx context.Context) error { return nil })

	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := decode(t, rec)
	if body["status"] != "ready" {
		t.Errorf("status = %v", body["status"])
	}
	checks := body["checks"].(map[string]any)
	if checks["db"] != "ok" || checks["outbox"] != "ok" {
		t.Errorf("checks = %v", checks)
	}
}

func TestReadiness_503WhenAnyCheckFails(t *testing.T) {
	h := newHandler()
	h.AddReadiness("db", func(ctx context.Context) error { return nil })
	h.AddReadiness("outbox", func(ctx context.Context) error { return errors.New("queue depth exceeded") })

	rec := httptest.NewRecorder()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	body := decode(t, rec)
	if body["status"] != "not_ready" {
		t.Errorf("status = %v, want not_ready", body["status"])
	}
	checks := body["checks"].(map[string]any)
	if checks["db"] != "ok" {
		t.Errorf("passing check should still be reported ok: %v", checks)
	}
	failMsg, _ := checks["outbox"].(string)
	if failMsg == "" || failMsg[:4] != "fail" {
		t.Errorf("failing check should prefix with 'fail': %v", checks)
	}
}

func TestReadiness_TimeoutSurfacedAsFail(t *testing.T) {
	h := newHandler()
	h.AddReadiness("slow", func(ctx context.Context) error {
		select {
		case <-time.After(5 * time.Second):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	rec := httptest.NewRecorder()
	start := time.Now()
	h.Readiness(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	elapsed := time.Since(start)

	if elapsed >= 3*time.Second {
		t.Errorf("Readiness should bound check time (~2s), took %v", elapsed)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}
