package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Row-level security (migration 0160): each organisation-owned table has a
// policy that shows a connection only the rows of the organisation set on it,
// and every row when none is set. Connections run as AppRole, which the
// policies bind; the organisation is set from the context each time a
// connection is taken from the pool.

// AppRole is the role the pool's connections run as.
const AppRole = "qeet_app"

// tenantSetting is the session setting the policies read.
const tenantSetting = "qeet.tenant_id"

type scopeKey struct{}

// WithTenant returns ctx scoped to tenantID: queries run with it see and write
// only that organisation's rows of the protected tables.
func WithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, scopeKey{}, tenantID.String())
}

// AcrossTenants returns ctx with no organisation scope, for the few requests
// that act across organisations by design, such as switching organisation or
// accepting an invitation to another.
func AcrossTenants(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopeKey{}, "")
}

// ScopedTo reports the organisation ctx is scoped to, if any.
func ScopedTo(ctx context.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(scopeOf(ctx))
	return id, err == nil
}

// scopeOf is the organisation ctx is scoped to, "" for none.
func scopeOf(ctx context.Context) string {
	s, _ := ctx.Value(scopeKey{}).(string)
	return s
}

// useAppRole runs a new connection as AppRole, so the policies apply to it.
func useAppRole(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, "SET ROLE "+AppRole)
	return err
}

// prepareScope sets the organisation of ctx on conn as it leaves the pool,
// unless conn already has it. A failure destroys the connection and fails the
// query, so nothing runs with another request's organisation.
func prepareScope(ctx context.Context, conn *pgx.Conn) (bool, error) {
	want := scopeOf(ctx)
	data := conn.PgConn().CustomData()
	if have, ok := data[tenantSetting].(string); ok && have == want {
		return true, nil
	}
	if _, err := conn.Exec(ctx, "SELECT set_config($1, $2, false)", tenantSetting, want); err != nil {
		return false, err
	}
	data[tenantSetting] = want
	return true, nil
}
