// Package identitylink holds the checks SAML, LDAP and social sign-in run on the
// account they would sign in, whether found by a linked identity or adopted by
// email. Emails are unique across tenants, so the account may belong elsewhere.
package identitylink

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Querier is the part of pgx.Tx and *pgxpool.Pool the checks need.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// HomeIn reports whether tenantID is userID's home tenant and the account isn't
// deleted. An organisation's identity provider vouches only for its own
// accounts: if it also signed in its guests (a role there, home elsewhere), that
// organisation's admin could assert a guest's address and switch the session
// into the guest's home. Callers must refuse the sign-in on false.
func HomeIn(ctx context.Context, q Querier, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM "user".users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)
	`, userID, tenantID).Scan(&ok)
	return ok, err
}

// AddressVerified reports whether userID has proved owning its email address.
// Adopting an account by email needs it, or a squatter who registered the
// address unverified would keep a working password on the adopted account.
func AddressVerified(ctx context.Context, q Querier, userID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM "user".users WHERE id = $1`, userID).Scan(&ok)
	return ok, err
}

// adminPermissions change who signs in to an organisation, or with what
// authority.
var adminPermissions = []string{"user.write", "role.write", "group.write", "connection.write", "policy.write", "tenant.write"}

// Administers reports whether userID owns tenantID or holds an admin
// permission there, directly or through a group. Single sign-on doesn't adopt
// such an account by its address, or whoever can configure a connection could
// assert an owner's address; it keeps its own credentials.
func Administers(ctx context.Context, q Querier, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles ur
			JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.tenant_id = ur.tenant_id
			LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
			LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2
			  AND ((ro.is_system AND ro.name = 'owner') OR p.key = ANY($3))
			UNION ALL
			SELECT 1 FROM tenant.group_members gm
			JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
			JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id
			LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
			LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE gm.user_id = $1 AND gm.tenant_id = $2
			  AND ((ro.is_system AND ro.name = 'owner') OR p.key = ANY($3))
		)`, userID, tenantID, adminPermissions).Scan(&ok)
	return ok, err
}
