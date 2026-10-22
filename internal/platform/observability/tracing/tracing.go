// Package tracing sets up OpenTelemetry tracing. It is off unless an OTLP
// endpoint is configured; trace-context propagation is installed either way, so
// upstream traces are still continued and forwarded.
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
	Endpoint    string  // OTLP/HTTP collector URL (OTEL_EXPORTER_OTLP_ENDPOINT); empty disables tracing
	ServiceName string  // the service.name resource attribute
	ServiceEnv  string  // the deployment.environment resource attribute
	SampleRatio float64 // head-sampling ratio for root spans, 0..1; child spans follow their parent
}

// Enabled reports whether tracing will export (an endpoint is configured).
func (c Config) Enabled() bool { return c.Endpoint != "" }

// noop is a shutdown that does nothing; returned when tracing is disabled.
func noop(context.Context) error { return nil }

// Init installs trace-context propagation and, if cfg.Endpoint is set, a global
// batching TracerProvider that exports over OTLP/HTTP. The returned shutdown
// flushes and stops it; with tracing disabled it is a no-op and nothing
// connects anywhere.
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
