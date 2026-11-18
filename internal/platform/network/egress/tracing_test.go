package egress

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestTracedTransportKeepsTheURLsSecretOut checks that an outbound call of a traced request is a span
// with its method, host and status only, never the path or query that can carry a customer's
// secret, and that no trace header reaches the third party; outside a traced request nothing is
// recorded.
func TestTracedTransportKeepsTheURLsSecretOut(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	var sent http.Header
	tr := tracedTransport{next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		sent = r.Header.Clone()
		return &http.Response{StatusCode: http.StatusAccepted, Body: http.NoBody}, nil
	})}
	call := func(ctx context.Context) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://hooks.example.com/in/abc?token=s3cr3t", nil)
		if res, err := tr.RoundTrip(req); err != nil {
			t.Fatal(err)
		} else {
			_ = res.Body.Close()
		}
	}

	call(context.Background())
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("a call outside a traced request recorded %d spans", n)
	}
	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")
	call(ctx)
	parent.End()

	var span sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		if s.Name() != "request" {
			span = s
		}
	}
	if span == nil || span.Name() != "HTTP POST hooks.example.com" {
		t.Fatalf("outbound span = %v, want HTTP POST hooks.example.com", span)
	}
	for _, a := range span.Attributes() {
		if v := a.Value.Emit(); strings.Contains(v, "s3cr3t") || strings.Contains(v, "/in/abc") {
			t.Errorf("span records the URL's path or query: %s=%s", a.Key, v)
		}
	}
	if sent.Get("traceparent") != "" {
		t.Error("a trace header was sent to the third party")
	}
}
