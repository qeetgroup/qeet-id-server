// Package rlsctx carries the tenant scope for Postgres Row-Level Security
// through the request context. It is a deliberately tiny leaf package (only the
// standard library + uuid) so both the HTTP layer (which resolves the tenant)
// and the database pool (which applies it as a session GUC on connection
// checkout) can import it without creating a dependency cycle.
//
// The value stored here is the tenant a request is *scoped to* — set by the
// EnforceTenantScope middleware only for routes carrying a validated
// {tenantID} path param. Requests without one (account-level, public, workers)
// carry no value, and the pool then runs them with RLS bypassed (they scope
// themselves by user id or operate cross-tenant by design).
package rlsctx

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey struct{}

// WithTenant returns a copy of ctx carrying the tenant the request is scoped to.
func WithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKey{}, tenantID)
}

// TenantFromContext returns the scoped tenant id and true if one was set.
func TenantFromContext(ctx context.Context) (uuid.UUID, bool) {
	tid, ok := ctx.Value(ctxKey{}).(uuid.UUID)
	return tid, ok
}
