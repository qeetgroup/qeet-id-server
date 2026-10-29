package rbac

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// editableRole locks tenantID's role roleID for a change: ErrNotFound for a
// role that isn't the tenant's, ErrRBACSystemRoleFixed for a built-in one.
func editableRole(ctx context.Context, q *dbgen.Queries, tenantID, roleID uuid.UUID) (dbgen.RbacRole, error) {
	row, err := q.LockRole(ctx, dbgen.LockRoleParams{ID: roleID, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errs.ErrNotFound
	}
	if err != nil {
		return row, err
	}
	if row.IsSystem {
		return row, errs.ErrRBACSystemRoleFixed
	}
	return row, nil
}

// SetPermissions makes permIDs the whole of tenantID's role roleID's
// permissions in one transaction, audited as one role.permissions_set naming
// what was added and removed, and returns them. mayGrant says which
// permissions the caller may add or take away; a built-in role is refused.
func (s *Service) SetPermissions(ctx context.Context, tenantID, roleID uuid.UUID, permIDs []uuid.UUID, mayGrant func(string) bool, actor audit.Actor) ([]Permission, error) {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.repo.q.WithTx(tx)

	if _, err := editableRole(ctx, q, tenantID, roleID); err != nil {
		return nil, err
	}
	want, err := q.PermissionsByID(ctx, permIDs)
	if err != nil {
		return nil, err
	}
	if len(want) != len(permIDs) {
		return nil, errs.ErrNotFound.WithDetail("a permission in permission_ids doesn't exist")
	}
	have, err := q.ListRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	var added, removed []uuid.UUID
	var addedKeys, removedKeys []string
	for _, p := range want {
		if !slices.ContainsFunc(have, func(h dbgen.RbacPermission) bool { return h.ID == p.ID }) {
			added, addedKeys = append(added, p.ID), append(addedKeys, p.Key)
		}
	}
	for _, p := range have {
		if !slices.ContainsFunc(want, func(w dbgen.RbacPermission) bool { return w.ID == p.ID }) {
			removed, removedKeys = append(removed, p.ID), append(removedKeys, p.Key)
		}
	}
	for _, key := range append(slices.Clone(addedKeys), removedKeys...) {
		if !mayGrant(key) {
			return nil, errs.ErrRBACGrantExceedsCaller.WithMetadata(map[string]any{"permission": key})
		}
	}

	out := make([]Permission, len(want))
	for i, p := range want {
		out[i] = toPermission(p)
	}
	if len(added) == 0 && len(removed) == 0 {
		return out, nil
	}
	if err := q.RevokePermissions(ctx, dbgen.RevokePermissionsParams{RoleID: roleID, PermissionIds: removed}); err != nil {
		return nil, err
	}
	if err := q.GrantPermissions(ctx, dbgen.GrantPermissionsParams{RoleID: roleID, PermissionIds: added}); err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.permissions_set", "role", roleID,
		map[string]any{"added": nonNil(addedKeys), "removed": nonNil(removedKeys)})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// UpdateRole renames tenantID's custom role roleID or changes its
// description, where name or description is set, audited as role.updated
// naming what changed. A built-in role is refused.
func (s *Service) UpdateRole(ctx context.Context, tenantID, roleID uuid.UUID, name, description *string, actor audit.Actor) (*Role, error) {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.repo.q.WithTx(tx)

	old, err := editableRole(ctx, q, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	next := dbgen.UpdateRoleParams{ID: roleID, TenantID: tenantID, Name: old.Name, Description: old.Description}
	changes := map[string]any{}
	if name != nil && *name != old.Name {
		next.Name = *name
		changes["name"] = map[string]any{"old": old.Name, "new": *name}
	}
	if description != nil && *description != old.Description {
		next.Description = *description
		changes["description"] = map[string]any{"old": old.Description, "new": *description}
	}
	if len(changes) == 0 {
		role := toRole(old)
		return &role, nil
	}
	row, err := q.UpdateRole(ctx, next)
	if pgxerr.IsUnique(err) {
		return nil, errs.ErrRBACRoleNameExists
	}
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.updated", "role", roleID, changes)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	role := toRole(row)
	return &role, nil
}

// DeleteRole deletes tenantID's custom role roleID, audited as role.deleted.
// It is refused with ErrRBACRoleInUse, counting them, while people, groups or
// open invitations hold it: someone whose only role it is would leave the
// organisation with it. A built-in role is refused.
func (s *Service) DeleteRole(ctx context.Context, tenantID, roleID uuid.UUID, actor audit.Actor) error {
	tx, err := s.repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.repo.q.WithTx(tx)

	role, err := editableRole(ctx, q, tenantID, roleID)
	if err != nil {
		return err
	}
	use, err := q.RoleUse(ctx, dbgen.RoleUseParams{RoleID: roleID, TenantID: tenantID})
	if err != nil {
		return err
	}
	if use.People > 0 || use.Groups > 0 || use.Invitations > 0 {
		return errs.ErrRBACRoleInUse.WithMetadata(map[string]any{
			"people": use.People, "groups": use.Groups, "invitations": use.Invitations,
		})
	}
	if err := q.DeleteRole(ctx, dbgen.DeleteRoleParams{ID: roleID, TenantID: tenantID}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "role.deleted", "role", roleID,
		map[string]any{"name": role.Name})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// nonNil is keys, or an empty list for none, so the audit record shows [].
func nonNil(keys []string) []string {
	if keys == nil {
		return []string{}
	}
	return keys
}
