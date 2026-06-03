// Package tracing wires OpenTelemetry distributed tracing for the service.
//
// It is OFF by default: with no OTLP endpoint configured, Init installs the
// global no-op tracer provider, sets propagators (so trace context is still
// honoured/forwarded if upstream supplies it), and returns a no-op shutdown.
// No exporter is built, nothing connects to a collector, and the app — plus
// tests/CI — boots and runs without any tracing backend present.
//
// When an endpoint is configured, Init builds an OTLP/HTTP exporter feeding a
// batching TracerProvider whose Resource carries service.name, with a
// ParentBased(TraceIDRatioBased) sampler. The returned shutdown flushes and
// closes the exporter and should be called during graceful shutdown.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Config controls tracing setup. The zero value (empty Endpoint) yields a
// no-op tracer.
type Config struct {
	// Endpoint is the OTLP/HTTP collector endpoint
	// (OTEL_EXPORTER_OTLP_ENDPOINT). Empty disables tracing (no exporter, no
	// network).
	Endpoint string
	// ServiceName is recorded as the service.name resource attribute.
	ServiceName string
	// ServiceEnv is recorded as deployment.environment.
	ServiceEnv string
	// SampleRatio is the head sampling ratio for root spans, 0..1. <=0 never
	// samples, >=1 always samples; values in between sample that fraction.
	// Spans inheriting a sampled parent are always recorded (ParentBased).
	SampleRatio float64
}

// Enabled reports whether tracing will export (an endpoint is configured).
func (c Config) Enabled() bool { return c.Endpoint != "" }

// noop is a shutdown that does nothing; returned when tracing is disabled.
func noop(context.Context) error { return nil }

// Init configures global tracing per cfg and returns a shutdown function.
//
// If cfg.Endpoint is empty, tracing is disabled: the global provider is left
// as the SDK default no-op, propagators are still installed, and a no-op
// shutdown is returned with a nil error. No exporter is created and nothing
// connects anywhere.
//
// Otherwise an OTLP/HTTP exporter + batching TracerProvider are installed
// globally and the returned shutdown flushes and stops them.
func Init(ctx context.Context, cfg Config) (shutdown func(context.Context) error, err error) {
	// Propagation works regardless of whether we export: it lets us continue
	// an upstream trace and forward context to downstream calls. Safe with the
	// no-op tracer too.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if !cfg.Enabled() {
		// No endpoint: leave the global no-op provider in place. Nothing to
		// flush, nothing connects.
		return noop, nil
	}

	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.DeploymentEnvironment(cfg.ServiceEnv),
	))
	if err != nil {
		// Schema mismatch between resource.Default() and our attributes; fall
		// back to just our attributes rather than failing startup.
		res = resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.DeploymentEnvironment(cfg.ServiceEnv),
		)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRatio))),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}
