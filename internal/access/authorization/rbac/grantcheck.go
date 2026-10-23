package rbac

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Nobody hands out authority they don't hold. Granting a permission to a role
// needs the caller to hold it; giving a role (directly, by group or by
// invitation) needs every permission it carries; only an owner gives the owner
// role. An owner may give anything; a machine caller holds only its scopes.

// CheckGrantPermission refuses, with ErrRBACGrantExceedsCaller naming it, the
// caller granting permID to a role of tenantID without holding it there.
func (r *Repository) CheckGrantPermission(ctx context.Context, caller *httpx.Principal, tenantID, permID uuid.UUID) error {
	var key string
	if err := r.pool.QueryRow(ctx, `SELECT key FROM rbac.permissions WHERE id = $1`, permID).Scan(&key); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		return err
	}
	return r.checkGrant(ctx, caller, tenantID, []string{key}, false)
}

// CheckGrantRole refuses the caller giving roleID of tenantID to anyone: with
// ErrRBACOwnerOnly for the owner role when the caller isn't an owner, and with
// ErrRBACGrantExceedsCaller naming a permission of the role the caller lacks.
// A role that isn't tenantID's passes, so the write itself must refuse it.
func (r *Repository) CheckGrantRole(ctx context.Context, caller *httpx.Principal, tenantID, roleID uuid.UUID) error {
	var ownerRole bool
	var keys []string
	err := r.pool.QueryRow(ctx, `
		SELECT (ro.is_system AND ro.name = 'owner'),
		       COALESCE(array_agg(p.key ORDER BY p.key) FILTER (WHERE p.key IS NOT NULL), '{}')
		FROM rbac.roles ro
		LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
		LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE ro.id = $1 AND ro.tenant_id = $2
		GROUP BY ro.id, ro.is_system, ro.name`, roleID, tenantID).Scan(&ownerRole, &keys)
	if errors.Is(err, pgx.ErrNoRows) {
		// The write answers for a role that isn't the tenant's, so a missing
		// and a foreign role get the same refusal.
		return nil
	}
	if err != nil {
		return err
	}
	return r.checkGrant(ctx, caller, tenantID, keys, ownerRole)
}

// checkGrant applies the rule above to the permissions being given.
func (r *Repository) checkGrant(ctx context.Context, caller *httpx.Principal, tenantID uuid.UUID, keys []string, ownerRole bool) error {
	if caller == nil {
		return errs.ErrRBACPermissionDenied
	}
	held := map[string]bool{}
	if caller.UserID != nil {
		owner, err := r.IsOwner(ctx, *caller.UserID, tenantID)
		if err != nil {
			return err
		}
		if owner {
			return nil
		}
		perms, err := r.EffectivePermissions(ctx, *caller.UserID, tenantID)
		if err != nil {
			return err
		}
		for _, p := range perms {
			held[p] = true
		}
	} else {
		for _, s := range caller.Scopes {
			held[s] = true
		}
	}
	if ownerRole {
		return errs.ErrRBACOwnerOnly
	}
	for _, k := range keys {
		if !held[k] {
			return errs.ErrRBACGrantExceedsCaller.WithMetadata(map[string]any{"permission": k})
		}
	}
	return nil
}

// IsOwner reports whether userID holds tenantID's owner role, directly or
// through a group.
func (r *Repository) IsOwner(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	var owner bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM rbac.user_roles ur
			JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.is_system AND ro.name = 'owner'
			WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND ro.tenant_id = $2
			UNION ALL
			SELECT 1 FROM tenant.group_members gm
			JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
			JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.is_system AND ro.name = 'owner'
			WHERE gm.user_id = $1 AND gm.tenant_id = $2 AND ro.tenant_id = $2
		)`, userID, tenantID).Scan(&owner)
	return owner, err
}
