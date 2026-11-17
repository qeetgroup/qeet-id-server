// Package identitylink holds the checks SAML, LDAP and social sign-in run on the
// account they would sign in, whether found by a linked identity or adopted by
// email. Emails are unique across tenants, so the account may belong elsewhere.
package identitylink

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Querier is the part of pgx.Tx and *pgxpool.Pool the checks need.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
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

// AddressVerified reports whether userID's email address is vouched for: the
// account proved owning it, or its organisation's directory provisioned it
// (SCIM). Adopting an account by email needs it, or a squatter who registered
// the address unverified would keep a working password on the adopted account.
func AddressVerified(ctx context.Context, q Querier, userID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT email_verified_at IS NOT NULL OR provisioned_via IS NOT DISTINCT FROM 'scim'
		FROM "user".users WHERE id = $1`, userID).Scan(&ok)
	return ok, err
}

// MarkAddressVerified records that userID's address is proved, when an
// organisation's identity provider adopting the account vouched for it.
func MarkAddressVerified(ctx context.Context, q Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx, `
		UPDATE "user".users SET email_verified_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND email_verified_at IS NULL`, userID)
	return err
}

// memberPermissions are the reads an account may hold and still be a member:
// every other permission, including one added in a later release, makes it an
// administrator. Secrets' read reveals them, so it administers.
var memberPermissions = []string{
	"tenant.read", "user.read", "role.read", "group.read", "connection.read", "apikey.read",
	"webhook.read", "billing.read", "policy.read", "audit.read", "analytics.read",
}

// MemberPermissions returns the permissions that don't administer an
// organisation: single sign-on neither adopts an account holding any other nor
// gives one by group, and domain capture counts the same administrators.
func MemberPermissions() []string { return slices.Clone(memberPermissions) }

// Administers reports whether userID owns tenantID or holds a permission
// outside MemberPermissions there, directly or through a group. Single sign-on
// doesn't adopt such an account by its address, or whoever can configure a
// connection could assert an owner's address; it keeps its own credentials.
func Administers(ctx context.Context, q Querier, userID, tenantID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles ur
			JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.tenant_id = ur.tenant_id
			LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
			LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2
			  AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY($3))))
			UNION ALL
			SELECT 1 FROM tenant.group_members gm
			JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
			JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id
			LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
			LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE gm.user_id = $1 AND gm.tenant_id = $2
			  AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY($3))))
		)`, userID, tenantID, memberPermissions).Scan(&ok)
	return ok, err
}

// ActOn refuses caller acting on targetID's account in tenantID when the target
// outranks them. Satisfied by rbac.Repository.CheckActOn.
type ActOn func(ctx context.Context, caller *httpx.Principal, tenantID, targetID uuid.UUID) error

// LinkedAdministrators returns the accounts that administer tenantID and are
// linked to its connection connID, or, when connID is uuid.Nil, to its social
// provider named provider: whatever that connection trusts can sign them in.
func LinkedAdministrators(ctx context.Context, q Querier, tenantID, connID uuid.UUID, provider string) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := q.QueryRow(ctx, `
		SELECT coalesce(array_agg(DISTINCT e.user_id), '{}') FROM "user".external_identities e
		WHERE e.tenant_id = $1
		  AND (e.connection_id = $2 OR ($2 = '00000000-0000-0000-0000-000000000000'::uuid AND e.connection_id IS NULL AND e.provider = $3))
		  AND (EXISTS (
		        SELECT 1 FROM rbac.user_roles ur
		        JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.tenant_id = ur.tenant_id
		        LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
		        LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
		        WHERE ur.user_id = e.user_id AND ur.tenant_id = $1
		          AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY($4)))))
		    OR EXISTS (
		        SELECT 1 FROM tenant.group_members gm
		        JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
		        JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id
		        LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
		        LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
		        WHERE gm.user_id = e.user_id AND gm.tenant_id = $1
		          AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY($4))))))`,
		tenantID, connID, provider, memberPermissions).Scan(&ids)
	return ids, err
}

// CheckTrustChange refuses caller changing what tenantID's connection (see
// LinkedAdministrators) trusts unless actOn lets them act on every
// administrator linked to it, as the changed connection could sign in as any
// of them. A caller who is no person (an admin-portal session) is refused
// whenever one is linked, as is every caller when actOn is nil.
func CheckTrustChange(ctx context.Context, q Querier, caller *httpx.Principal, actOn ActOn, tenantID, connID uuid.UUID, provider string) error {
	admins, err := LinkedAdministrators(ctx, q, tenantID, connID, provider)
	if err != nil || len(admins) == 0 {
		return err
	}
	if actOn == nil || caller == nil || caller.UserID == nil {
		return errs.ErrRBACTrustChangeOutranks
	}
	for _, id := range admins {
		if err := actOn(ctx, caller, tenantID, id); err != nil {
			if errors.Is(err, errs.ErrRBACTargetIsOwner) || errors.Is(err, errs.ErrRBACTargetOutranks) {
				return errs.ErrRBACTrustChangeOutranks
			}
			return err
		}
	}
	return nil
}
