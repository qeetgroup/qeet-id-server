package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestQueryName(t *testing.T) {
	for sql, want := range map[string][2]string{
		"-- name: GetUserByEmail :one\nSELECT id FROM account.users WHERE email = $1": {"GetUserByEmail", "SELECT"},
		"  update account.users set name = $1":                                         {"UPDATE", "UPDATE"},
		"(SELECT 1) UNION (SELECT 2)":                                                   {"SELECT", "SELECT"},
		"":                                                                              {"SQL", "SQL"},
	} {
		if name, op := queryName(sql); name != want[0] || op != want[1] {
			t.Errorf("queryName(%q) = %s, %s; want %s, %s", sql, name, op, want[0], want[1])
		}
	}
}

// TestQueryTracerRecordsOnlyTracedQueriesWithoutTheirValues checks that a query outside a traced
// request records nothing, that one inside is a span named after its query, and that a failure
// records its SQLSTATE but never PostgreSQL's message, which can quote the values.
func TestQueryTracerRecordsOnlyTracedQueriesWithoutTheirValues(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	var qt queryTracer
	run := func(ctx context.Context, sql string, err error) {
		ctx = qt.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: sql, Args: []any{"someone@example.com"}})
		qt.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{Err: err})
	}

	run(context.Background(), "-- name: GetUser :one\nSELECT 1", nil)
	if n := len(rec.Ended()); n != 0 {
		t.Fatalf("a query outside a traced request recorded %d spans", n)
	}

	ctx, parent := otel.Tracer("test").Start(context.Background(), "request")
	run(ctx, "-- name: GetUser :one\nSELECT 1", nil)
	run(ctx, "-- name: InsertUser :exec\nINSERT INTO account.users (email) VALUES ($1)",
		&pgconn.PgError{Code: "23505", Message: `duplicate key value violates unique constraint "users_email_key"`, Detail: "Key (email)=(someone@example.com) already exists."})
	run(ctx, "-- name: GetMissing :one\nSELECT 1", pgx.ErrNoRows)
	parent.End()

	spans := map[string]sdktrace.ReadOnlySpan{}
	for _, s := range rec.Ended() {
		spans[s.Name()] = s
		for _, a := range s.Attributes() {
			if strings.Contains(a.Value.Emit(), "someone@example.com") {
				t.Errorf("span %s records a value: %s=%s", s.Name(), a.Key, a.Value.Emit())
			}
		}
		if strings.Contains(s.Status().Description, "example.com") {
			t.Errorf("span %s status quotes a value: %q", s.Name(), s.Status().Description)
		}
	}
	if s, ok := spans["postgres GetUser"]; !ok || s.Parent().SpanID() != parent.SpanContext().SpanID() || s.Status().Code == codes.Error {
		t.Errorf("GetUser span = %v (found %v), want a child of the request, not failed", s, ok)
	}
	if s := spans["postgres InsertUser"]; s == nil || s.Status().Code != codes.Error || s.Status().Description != "23505" {
		t.Errorf("a failed query: status %+v, want error 23505", s)
	}
	if s := spans["postgres GetMissing"]; s == nil || s.Status().Code == codes.Error {
		t.Error("no rows is an answer, not a failure")
	}
}
