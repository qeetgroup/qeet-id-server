package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac/dbgen"
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
// caller granting permID to a role of organizationID without holding it there.
func (r *Repository) CheckGrantPermission(ctx context.Context, caller *httpx.Principal, organizationID, permID uuid.UUID) error {
	key, err := r.q.GetPermissionKey(ctx, permID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		return err
	}
	return r.checkGrant(ctx, caller, organizationID, []string{key}, false)
}

// CheckGrantRole refuses the caller giving roleID of organizationID to anyone: with
// ErrRBACOwnerOnly for the owner role when the caller isn't an owner, and with
// ErrRBACGrantExceedsCaller naming a permission of the role the caller lacks.
// A role that isn't organizationID's passes, so the write itself must refuse it.
func (r *Repository) CheckGrantRole(ctx context.Context, caller *httpx.Principal, organizationID, roleID uuid.UUID) error {
	role, err := r.q.RoleGrantScope(ctx, dbgen.RoleGrantScopeParams{RoleID: roleID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		// The write answers for a role that isn't the organization's, so a missing
		// and a foreign role get the same refusal.
		return nil
	}
	if err != nil {
		return err
	}
	return r.checkGrant(ctx, caller, organizationID, role.Keys, role.OwnerRole)
}

// CheckGrantGroup refuses the caller adding someone to groupID of organizationID when
// the group's roles carry authority the caller doesn't hold: ErrRBACOwnerOnly
// for a group holding the owner role, ErrRBACGrantExceedsCaller naming a
// permission otherwise. A group that isn't organizationID's passes, so the write
// itself must refuse it.
func (r *Repository) CheckGrantGroup(ctx context.Context, caller *httpx.Principal, organizationID, groupID uuid.UUID) error {
	group, err := r.q.GroupGrantScope(ctx, dbgen.GroupGrantScopeParams{GroupID: groupID, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	return r.checkGrant(ctx, caller, organizationID, group.Keys, group.OwnerRole)
}

// CheckActOn refuses the caller changing targetID's account or roles in
// organizationID when the target outranks them: ErrRBACTargetIsOwner for an owner
// unless the caller is one, ErrRBACTargetOutranks naming a permission the
// target holds and the caller doesn't. A person acting on themselves passes.
func (r *Repository) CheckActOn(ctx context.Context, caller *httpx.Principal, organizationID, targetID uuid.UUID) error {
	if caller == nil {
		return errs.ErrRBACPermissionDenied
	}
	if caller.UserID != nil && *caller.UserID == targetID && !machineActor(caller.ActorType) {
		return nil
	}
	g, err := r.grantorOf(ctx, caller, organizationID)
	if err != nil || g.all {
		return err
	}
	owner, err := r.IsOwner(ctx, targetID, organizationID)
	if err != nil {
		return err
	}
	if owner {
		return errs.ErrRBACTargetIsOwner
	}
	perms, err := r.EffectivePermissions(ctx, targetID, organizationID)
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

// CheckRoleEditable refuses changing roleID of organizationID when it is one of the
// built-in roles (owner, admin, member, viewer), with ErrRBACSystemRoleFixed.
// A role that isn't organizationID's passes, so the write itself must refuse it.
func (r *Repository) CheckRoleEditable(ctx context.Context, organizationID, roleID uuid.UUID) error {
	fixed, err := r.q.RoleIsSystem(ctx, dbgen.RoleIsSystemParams{RoleID: roleID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if fixed {
		return ErrSystemRoleFixed
	}
	return nil
}

// CheckGrantScopes refuses the caller issuing a machine credential of organizationID
// that carries a scope the caller doesn't hold, with ErrRBACGrantExceedsCaller
// naming it. A vault scope needs secret.read, or for a credential a vault scope
// covering it.
func (r *Repository) CheckGrantScopes(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error {
	return r.checkGrant(ctx, caller, organizationID, scopes, false)
}

// Grantable reports which permissions the caller may give or take away in
// organizationID, under the rule above, for a change worked out in a transaction.
func (r *Repository) Grantable(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID) (func(key string) bool, error) {
	if caller == nil {
		return nil, errs.ErrRBACPermissionDenied
	}
	g, err := r.grantorOf(ctx, caller, organizationID)
	if err != nil {
		return nil, err
	}
	return g.holds, nil
}

// checkGrant applies the rule above to the permissions or scopes being given.
func (r *Repository) checkGrant(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, keys []string, ownerRole bool) error {
	if caller == nil {
		return errs.ErrRBACPermissionDenied
	}
	g, err := r.grantorOf(ctx, caller, organizationID)
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

// grantorOf is what caller may hand out in organizationID.
func (r *Repository) grantorOf(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID) (grantor, error) {
	person := func(userID uuid.UUID) (grantor, error) {
		owner, err := r.IsOwner(ctx, userID, organizationID)
		if err != nil || owner {
			return grantor{all: owner}, err
		}
		perms, err := r.EffectivePermissions(ctx, userID, organizationID)
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

// IsOwner reports whether userID holds organizationID's owner role, directly or
// through a group.
func (r *Repository) IsOwner(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	return r.q.IsOwner(ctx, dbgen.IsOwnerParams{UserID: userID, OrganizationID: organizationID})
}
