package egress

import (
	"net/http"
	"strconv"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracedTransport records each outbound call of a traced request as a span with its method, host
// and status only: a URL's path and query can carry a customer's secret (a webhook token), so they
// are never recorded. No trace header is sent to the third party.
type tracedTransport struct{ next http.RoundTripper }

// RoundTrip implements http.RoundTripper.
func (t tracedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return t.next.RoundTrip(r)
	}
	ctx, span := otel.Tracer("github.com/qeetgroup/qeet-id-server/egress").Start(ctx, "HTTP "+r.Method+" "+r.URL.Hostname(),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("server.address", r.URL.Hostname())))
	defer span.End()
	res, err := t.next.RoundTrip(r.WithContext(ctx))
	if err != nil {
		span.SetStatus(codes.Error, "transport error")
		return res, err
	}
	span.SetAttributes(attribute.Int("http.response.status_code", res.StatusCode))
	if res.StatusCode >= 500 {
		span.SetStatus(codes.Error, strconv.Itoa(res.StatusCode))
	}
	return res, nil
}
