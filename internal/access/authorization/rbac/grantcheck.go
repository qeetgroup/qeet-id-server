package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Nobody hands out authority they don't hold. Granting a permission to a role
// needs the caller to hold it; giving a role (directly, by group or by
// invitation, or by adding them to a group that holds it) needs every
// permission it carries; issuing a machine credential
// needs every scope it carries; only an owner gives the owner role. A person
// holds their permissions, an owner everything; a credential (API key, service
// principal, agent) holds only its scopes, and no more than the person it acts
// for holds now.

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

// CheckGrantGroup refuses the caller adding someone to groupID of tenantID when
// the group's roles carry authority the caller doesn't hold: ErrRBACOwnerOnly
// for a group holding the owner role, ErrRBACGrantExceedsCaller naming a
// permission otherwise. A group that isn't tenantID's passes, so the write
// itself must refuse it.
func (r *Repository) CheckGrantGroup(ctx context.Context, caller *httpx.Principal, tenantID, groupID uuid.UUID) error {
	var ownerRole bool
	var keys []string
	if err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(bool_or(ro.is_system AND ro.name = 'owner'), false),
		       COALESCE(array_agg(DISTINCT p.key) FILTER (WHERE p.key IS NOT NULL), '{}')
		FROM rbac.group_roles gr
		JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id
		LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
		LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE gr.group_id = $1 AND gr.tenant_id = $2`, groupID, tenantID).Scan(&ownerRole, &keys); err != nil {
		return err
	}
	return r.checkGrant(ctx, caller, tenantID, keys, ownerRole)
}

// CheckActOn refuses the caller changing targetID's account or roles in
// tenantID when the target outranks them: ErrRBACTargetIsOwner for an owner
// unless the caller is one, ErrRBACTargetOutranks naming a permission the
// target holds and the caller doesn't. A person acting on themselves passes.
func (r *Repository) CheckActOn(ctx context.Context, caller *httpx.Principal, tenantID, targetID uuid.UUID) error {
	if caller == nil {
		return errs.ErrRBACPermissionDenied
	}
	if caller.UserID != nil && *caller.UserID == targetID && !machineActor(caller.ActorType) {
		return nil
	}
	g, err := r.grantorOf(ctx, caller, tenantID)
	if err != nil || g.all {
		return err
	}
	owner, err := r.IsOwner(ctx, targetID, tenantID)
	if err != nil {
		return err
	}
	if owner {
		return errs.ErrRBACTargetIsOwner
	}
	perms, err := r.EffectivePermissions(ctx, targetID, tenantID)
	if err != nil {
		return err
	}
	for _, p := range perms {
		if !g.holds(p) {
			return errs.ErrRBACTargetOutranks.WithMetadata(map[string]any{"permission": p})
		}
	}
	return nil
}

// CheckRoleEditable refuses changing roleID of tenantID when it is one of the
// built-in roles (owner, admin, member, viewer), with ErrRBACSystemRoleFixed.
// A role that isn't tenantID's passes, so the write itself must refuse it.
func (r *Repository) CheckRoleEditable(ctx context.Context, tenantID, roleID uuid.UUID) error {
	var fixed bool
	err := r.pool.QueryRow(ctx, `SELECT is_system FROM rbac.roles WHERE id = $1 AND tenant_id = $2`, roleID, tenantID).Scan(&fixed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if fixed {
		return errs.ErrRBACSystemRoleFixed
	}
	return nil
}

// CheckGrantScopes refuses the caller issuing a machine credential of tenantID
// that carries a scope the caller doesn't hold, with ErrRBACGrantExceedsCaller
// naming it. A vault scope needs secret.read, or for a credential a vault scope
// covering it.
func (r *Repository) CheckGrantScopes(ctx context.Context, caller *httpx.Principal, tenantID uuid.UUID, scopes []string) error {
	return r.checkGrant(ctx, caller, tenantID, scopes, false)
}

// Grantable reports which permissions the caller may give or take away in
// tenantID, under the rule above, for a change worked out in a transaction.
func (r *Repository) Grantable(ctx context.Context, caller *httpx.Principal, tenantID uuid.UUID) (func(key string) bool, error) {
	if caller == nil {
		return nil, errs.ErrRBACPermissionDenied
	}
	g, err := r.grantorOf(ctx, caller, tenantID)
	if err != nil {
		return nil, err
	}
	return g.holds, nil
}

// checkGrant applies the rule above to the permissions or scopes being given.
func (r *Repository) checkGrant(ctx context.Context, caller *httpx.Principal, tenantID uuid.UUID, keys []string, ownerRole bool) error {
	if caller == nil {
		return errs.ErrRBACPermissionDenied
	}
	g, err := r.grantorOf(ctx, caller, tenantID)
	if err != nil {
		return err
	}
	if g.all {
		return nil
	}
	if ownerRole {
		return errs.ErrRBACOwnerOnly
	}
	for _, k := range keys {
		if !g.holds(k) {
			return errs.ErrRBACGrantExceedsCaller.WithMetadata(map[string]any{"permission": k})
		}
	}
	return nil
}

// grantor is what a caller may hand out.
type grantor struct {
	all     bool // an owner, acting in person
	machine bool // a credential: held are its scopes
	held    map[string]bool
}

// holds reports whether the grantor may hand out key, a permission or scope.
func (g grantor) holds(key string) bool {
	if g.all || g.held[key] {
		return true
	}
	if name, ok := strings.CutPrefix(key, "vault:"); ok && name != "" {
		if g.machine {
			return g.held["vault:read"]
		}
		return g.held["secret.read"]
	}
	return false
}

// grantorOf is what caller may hand out in tenantID.
func (r *Repository) grantorOf(ctx context.Context, caller *httpx.Principal, tenantID uuid.UUID) (grantor, error) {
	person := func(userID uuid.UUID) (grantor, error) {
		owner, err := r.IsOwner(ctx, userID, tenantID)
		if err != nil || owner {
			return grantor{all: owner}, err
		}
		perms, err := r.EffectivePermissions(ctx, userID, tenantID)
		if err != nil {
			return grantor{}, err
		}
		g := grantor{held: make(map[string]bool, len(perms))}
		for _, p := range perms {
			g.held[p] = true
		}
		return g, nil
	}
	if caller.UserID != nil && !machineActor(caller.ActorType) {
		return person(*caller.UserID)
	}
	g := grantor{machine: true, held: make(map[string]bool, len(caller.Scopes))}
	var bound *grantor
	if caller.UserID != nil {
		p, err := person(*caller.UserID)
		if err != nil {
			return grantor{}, err
		}
		bound = &p
	}
	for _, s := range caller.Scopes {
		if bound == nil || bound.holds(s) {
			g.held[s] = true
		}
	}
	return g, nil
}

// machineActor reports whether actorType is a credential's, which acts by its
// scopes rather than as a person signed in.
func machineActor(actorType string) bool {
	switch actorType {
	case "api_key", "service", "service_principal", "agent":
		return true
	}
	return false
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
