package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Row-level security (migration 0011): each organization-owned table has a
// policy that shows a connection only the rows of the organization set on it,
// and every row when none is set. Connections run as AppRole, which the
// policies bind; the organization is set from the context each time a
// connection is taken from the pool.

// AppRole is the role the pool's connections run as.
const AppRole = "qeet_app"

// organizationSetting is the session setting the policies read.
const organizationSetting = "qeet.organization_id"

type scopeKey struct{}

// WithOrganization returns ctx scoped to organizationID: queries run with it see and write
// only that organization's rows of the protected tables.
func WithOrganization(ctx context.Context, organizationID uuid.UUID) context.Context {
	return context.WithValue(ctx, scopeKey{}, organizationID.String())
}

// AcrossOrganizations returns ctx with no organization scope, for the few requests
// that act across organizations by design, such as switching organization or
// accepting an invitation to another.
func AcrossOrganizations(ctx context.Context) context.Context {
	return context.WithValue(ctx, scopeKey{}, "")
}

// ScopedTo reports the organization ctx is scoped to, if any.
func ScopedTo(ctx context.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(scopeOf(ctx))
	return id, err == nil
}

// scopeOf is the organization ctx is scoped to, "" for none.
func scopeOf(ctx context.Context) string {
	s, _ := ctx.Value(scopeKey{}).(string)
	return s
}

// useAppRole runs a new connection as AppRole, so the policies apply to it.
func useAppRole(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, "SET ROLE "+AppRole)
	return err
}

// prepareScope sets the organization of ctx on conn as it leaves the pool,
// unless conn already has it. A failure destroys the connection and fails the
// query, so nothing runs with another request's organization.
func prepareScope(ctx context.Context, conn *pgx.Conn) (bool, error) {
	want := scopeOf(ctx)
	data := conn.PgConn().CustomData()
	if have, ok := data[organizationSetting].(string); ok && have == want {
		return true, nil
	}
	if _, err := conn.Exec(ctx, "SELECT set_config($1, $2, false)", organizationSetting, want); err != nil {
		return false, err
	}
	data[organizationSetting] = want
	return true, nil
}
