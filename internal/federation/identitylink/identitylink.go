// Package identitylink holds the tenant-adoption guard shared by every
// federated login path (SAML SP, LDAP, social/OIDC).
//
// # Why this package exists
//
// Emails are globally unique platform-wide (migration 0022_global_email), so
// looking a user up by the email address an external IdP asserted can return a
// user owned by a *completely different tenant*. Each federated login flow
// therefore has to answer one question before it adopts that row: does this
// user actually belong to the tenant this login is for?
//
// Historically each flow carried its own copy of findOrCreateUser and its own
// answer. Social got the check; SAML and LDAP were written as "mirrors" of it
// and did not — which meant a tenant admin could register an IdP they control,
// assert another tenant's user's address, and be handed a token pair carrying
// that user's id. The check lives here, once, so the three flows cannot drift
// apart again.
package identitylink

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Querier is the subset of pgx.Tx / pgxpool.Pool this package needs. Declaring
// it here (consumer side) lets callers pass whichever they already hold.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// UserInTenant reports whether userID belongs to tenantID.
//
// Two things count:
//
//   - the user's home tenant ("user".users.tenant_id), which is what a
//     federation-provisioned user gets and what a repeat login has to match;
//   - an rbac.user_roles grant, which is how a guest becomes a member.
//
// Requiring only the latter would reject a user the flow itself just
// provisioned, since provisioning grants no role.
//
// Callers MUST treat a false result as a hard failure and refuse the login.
// Returning the user id anyway is a cross-tenant account takeover.
func UserInTenant(ctx context.Context, q Querier, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM "user".users u
			WHERE u.id = $1 AND u.deleted_at IS NULL AND u.tenant_id = $2
			UNION ALL
			SELECT 1 FROM rbac.user_roles ur
			WHERE ur.user_id = $1 AND ur.tenant_id = $2
		)
	`, userID, tenantID).Scan(&ok)
	return ok, err
}
