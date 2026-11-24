package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// queryTracer records each query of a traced request as a span named after it: the sqlc query
// ("postgres GetUserByEmail") or, for other SQL, its first keyword. Arguments are never recorded,
// and a failure records only its SQLSTATE, as PostgreSQL's message can quote the values.
type queryTracer struct{}

type tracedQuery struct{}

// TraceQueryStart implements pgx.QueryTracer. Outside a traced request it records nothing.
func (queryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ctx
	}
	name, operation := queryName(data.SQL)
	ctx, _ = otel.Tracer("github.com/qeetgroup/qeet-id-server/postgres").Start(ctx, "postgres "+name,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("db.system.name", "postgresql"), attribute.String("db.operation.name", operation)))
	return context.WithValue(ctx, tracedQuery{}, true)
}

// TraceQueryEnd implements pgx.QueryTracer.
func (queryTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(tracedQuery{}) == nil {
		return
	}
	span := trace.SpanFromContext(ctx)
	if data.Err != nil && !errors.Is(data.Err, pgx.ErrNoRows) {
		var pgErr *pgconn.PgError
		code := "error"
		if errors.As(data.Err, &pgErr) {
			code = pgErr.Code
		}
		span.SetAttributes(attribute.String("db.response.status_code", code))
		span.SetStatus(codes.Error, code)
	}
	span.End()
}

// queryName is the sqlc name of sql ("-- name: GetUser :one") and its operation, or for other SQL
// its first keyword for both.
func queryName(sql string) (name, operation string) {
	s := strings.TrimSpace(sql)
	if rest, ok := strings.CutPrefix(s, "-- name: "); ok {
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			name = fields[0]
		}
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			s = strings.TrimSpace(rest[i+1:])
		}
	}
	operation = "SQL"
	if fields := strings.Fields(s); len(fields) > 0 {
		operation = strings.ToUpper(strings.Trim(fields[0], "("))
	}
	if name == "" {
		name = operation
	}
	return name, operation
}
