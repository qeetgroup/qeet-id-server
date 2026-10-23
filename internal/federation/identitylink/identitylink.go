// Package identitylink holds the check SAML, LDAP and social sign-in run before
// adopting an existing account by email. Emails are unique across tenants, so the
// matched user may belong to a different tenant from the one signing in.
package identitylink

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Querier is the part of pgx.Tx and *pgxpool.Pool that UserInTenant needs.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// UserInTenant reports whether userID belongs to tenantID: it is the user's home
// tenant (which federation-provisioned users get, since provisioning grants no
// role) or the user holds a role there. Callers must refuse the sign-in on
// false, or one tenant's IdP could take over another tenant's account.
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
