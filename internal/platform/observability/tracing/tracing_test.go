package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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
	if otel.GetTextMapPropagator() == nil {
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

// TestInit_ExportsToTheTracesPath checks that a collector's base URL, as OTEL_EXPORTER_OTLP_ENDPOINT
// is usually set, receives the spans at /v1/traces, and that a full traces URL is used as it is.
func TestInit_ExportsToTheTracesPath(t *testing.T) {
	for _, c := range []struct{ suffix, want string }{
		{"", "/v1/traces"},
		{"/", "/v1/traces"},
		{"/custom/v1/traces", "/custom/v1/traces"},
	} {
		got := make(chan string, 4)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- r.URL.Path
			w.WriteHeader(http.StatusOK)
		}))
		ctx := context.Background()
		shutdown, err := Init(ctx, Config{Endpoint: srv.URL + c.suffix, ServiceName: "qeet-id-test", SampleRatio: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, span := otel.Tracer("test").Start(ctx, "span")
		span.End()
		if err := shutdown(ctx); err != nil {
			t.Fatalf("endpoint %q: flush: %v", c.suffix, err)
		}
		srv.Close()
		select {
		case path := <-got:
			if path != c.want {
				t.Errorf("endpoint %q: spans sent to %s, want %s", c.suffix, path, c.want)
			}
		default:
			t.Errorf("endpoint %q: no spans were sent", c.suffix)
		}
	}
}

// A caller's trace header isn't this server's to obey: with sampling off it turns none on for the
// caller's requests, which would let anyone fill the trace store and choose the trace they join.
func TestCallersTraceHeaderDoesNotTurnSamplingOn(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0))))
	wasProvider, wasPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(wasProvider)
		otel.SetTextMapPropagator(wasPropagator)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/anything", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), req)

	if spans := recorder.Ended(); len(spans) != 0 {
		t.Errorf("a caller's sampled trace header recorded %d span(s) in trace %s, want none with sampling off",
			len(spans), spans[0].SpanContext().TraceID())
	}
}
