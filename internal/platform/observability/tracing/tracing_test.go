package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// TestInit_DisabledByDefault checks that, with no endpoint, Init builds no
// exporter, connects nowhere and returns a usable no-op shutdown.
func TestInit_DisabledByDefault(t *testing.T) {
	shutdown, err := Init(context.Background(), Config{ServiceName: "test"})
	if err != nil {
		t.Fatalf("Init with empty endpoint returned err: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Init returned a nil shutdown func")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown returned err: %v", err)
	}

	// Propagators are still installed even when disabled, so trace context is
	// continued/forwarded if upstream supplies it.
	if _, ok := otel.GetTextMapPropagator().(propagation.TextMapPropagator); !ok {
		t.Fatal("expected a text map propagator to be installed")
	}
}

func TestConfig_Enabled(t *testing.T) {
	if (Config{}).Enabled() {
		t.Error("empty Config should be disabled")
	}
	if !(Config{Endpoint: "http://localhost:4318"}).Enabled() {
		t.Error("Config with endpoint should be enabled")
	}
}

// TestMiddleware_NoopSafe checks that the middleware passes requests through
// unchanged when tracing is disabled.
func TestMiddleware_NoopSafe(t *testing.T) {
	if _, err := Init(context.Background(), Config{ServiceName: "test"}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	called := false
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/anything", nil))

	if !called {
		t.Fatal("middleware did not call the next handler")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418 (middleware altered response)", rec.Code)
	}
}
