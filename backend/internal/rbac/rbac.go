// Package rbac models permissions, per-tenant roles, role->permission
// bindings, and user assignments. The Check endpoint is the hot path
// callers use to authorize an action.
//
// Mutating methods take a pgx.Tx so the caller (HTTP handler) can wrap
// the mutation plus its audit row in a single transaction. Read methods
// use the pool directly.
package rbac

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/pgxerr"
)

type Permission struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Description string    `json:"description"`
}

type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an RBAC mutation and its audit row.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

func (r *Repository) UpsertPermission(ctx context.Context, tx pgx.Tx, key, desc string) (*Permission, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO rbac.permissions (key, description)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description
		RETURNING id, key, description
	`, key, desc)
	var p Permission
	if err := row.Scan(&p.ID, &p.Key, &p.Description); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *Repository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, key, description FROM rbac.permissions ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Key, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (r *Repository) CreateRole(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, name, desc string, isSystem bool) (*Role, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, name, description, is_system, created_at
	`, tenantID, name, desc, isSystem)
	var role Role
	if err := row.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt); err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("role name exists for tenant")
		}
		return nil, err
	}
	return &role, nil
}

func (r *Repository) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, tenant_id, name, description, is_system, created_at
		FROM rbac.roles
		WHERE tenant_id = $1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.TenantID, &role.Name, &role.Description, &role.IsSystem, &role.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, nil
}

func (r *Repository) GrantPermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO rbac.role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, roleID, permID)
	return err
}

func (r *Repository) RevokePermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM rbac.role_permissions WHERE role_id = $1 AND permission_id = $2
	`, roleID, permID)
	return err
}

func (r *Repository) AssignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id, granted_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING
	`, userID, tenantID, roleID, grantedBy)
	return err
}

func (r *Repository) UnassignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3
	`, userID, tenantID, roleID)
	return err
}

// AssignRoleToGroup grants a role to a group. The role and the group must both
// belong to tenantID; we enforce that in the INSERT's SELECT so a caller can
// never bind a role from one tenant to a group in another. ON CONFLICT keeps it
// idempotent. The returned bool reports whether the role/group pair was valid
// for this tenant (false => the caller should surface a 404), distinguishing a
// genuine no-op from a cross-tenant or missing-row attempt.
func (r *Repository) AssignRoleToGroup(ctx context.Context, tx pgx.Tx, groupID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID) (bool, error) {
	var valid bool
	err := tx.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO rbac.group_roles (tenant_id, group_id, role_id, granted_by)
			SELECT $2, $1, $3, $4
			WHERE EXISTS (SELECT 1 FROM tenant.groups g WHERE g.id = $1 AND g.tenant_id = $2)
			  AND EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = $3 AND ro.tenant_id = $2)
			ON CONFLICT DO NOTHING
			RETURNING 1
		)
		SELECT
			EXISTS (SELECT 1 FROM ins)
			OR EXISTS (SELECT 1 FROM rbac.group_roles WHERE group_id = $1 AND role_id = $3 AND tenant_id = $2)
	`, groupID, tenantID, roleID, grantedBy).Scan(&valid)
	if err != nil {
		return false, err
	}
	return valid, nil
}

// RemoveRoleFromGroup revokes a role from a group within a tenant.
func (r *Repository) RemoveRoleFromGroup(ctx context.Context, tx pgx.Tx, groupID, tenantID, roleID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM rbac.group_roles WHERE group_id = $1 AND tenant_id = $2 AND role_id = $3
	`, groupID, tenantID, roleID)
	return err
}

// GroupRole is a role bound to a group, enriched with the role's name so the
// admin UI can render it without a follow-up call.
type GroupRole struct {
	RoleID    uuid.UUID `json:"role_id"`
	Name      string    `json:"name"`
	GrantedAt time.Time `json:"granted_at"`
}

// ListGroupRoles returns every role granted to a group within a tenant.
func (r *Repository) ListGroupRoles(ctx context.Context, groupID, tenantID uuid.UUID) ([]GroupRole, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT gr.role_id, ro.name, gr.granted_at
		FROM rbac.group_roles gr
		JOIN rbac.roles ro ON ro.id = gr.role_id
		WHERE gr.group_id = $1 AND gr.tenant_id = $2
		ORDER BY ro.name
	`, groupID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupRole
	for rows.Next() {
		var g GroupRole
		if err := rows.Scan(&g.RoleID, &g.Name, &g.GrantedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// Check returns true if the user holds any role in tenant that grants the
// named permission — counting BOTH roles granted directly to the user and
// roles granted to a group the user belongs to. The two arms are scoped by
// tenant_id independently so a grant can never leak across tenants.
func (r *Repository) Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM rbac.user_roles ur
			JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
			JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND p.key = $3
			UNION ALL
			SELECT 1
			FROM tenant.group_members gm
			JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
			JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
			JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE gm.user_id = $1 AND gm.tenant_id = $2 AND p.key = $3
		)
	`, userID, tenantID, permKey).Scan(&ok)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return ok, nil
}

// EffectivePermissions returns all permission keys granted to a user within a
// tenant — via roles granted directly to the user UNION roles granted to any
// group the user belongs to.
func (r *Repository) EffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT p.key
		FROM rbac.user_roles ur
		JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
		JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
		UNION
		SELECT p.key
		FROM tenant.group_members gm
		JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
		JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
		JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE gm.user_id = $1 AND gm.tenant_id = $2
		ORDER BY key
	`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// GrantStep is one link in an authorization decision's grant path: a role that
// confers the requested permission, plus how that role reaches the user.
type GrantStep struct {
	Permission string     `json:"permission"`
	GrantedBy  string     `json:"granted_by"` // e.g. "role:admin"
	Via        string     `json:"via"`        // "direct" or "group:<name>"
	GroupID    *uuid.UUID `json:"group_id,omitempty"`
	RoleID     uuid.UUID  `json:"role_id"`
}

// Explanation is the structured "why?" for a single Check. Allowed is the same
// boolean the hot-path Check returns; Paths lists every distinct grant that
// confers the permission (direct and group-derived), and Reason is set only on
// a denial.
type Explanation struct {
	Allowed bool        `json:"allowed"`
	Paths   []GrantStep `json:"paths"`
	Reason  string      `json:"reason,omitempty"`
}

// Explain resolves the same decision as Check but records the grant path while
// it computes it (rather than re-deriving), so it stays correct as the rules
// evolve. It enumerates every role — direct or group-derived — that grants the
// permission for this user/tenant. allowed == (len(Paths) > 0). Both arms are
// scoped by tenant_id, so a path can never name a grant from another tenant.
func (r *Repository) Explain(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (*Explanation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT 'direct'::text AS via, NULL::uuid AS group_id, NULL::text AS group_name, ro.id, ro.name
		FROM rbac.user_roles ur
		JOIN rbac.roles ro ON ro.id = ur.role_id
		JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
		JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND p.key = $3
		UNION ALL
		SELECT 'group'::text AS via, g.id AS group_id, g.name AS group_name, ro.id, ro.name
		FROM tenant.group_members gm
		JOIN tenant.groups g ON g.id = gm.group_id AND g.tenant_id = gm.tenant_id
		JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
		JOIN rbac.roles ro ON ro.id = gr.role_id
		JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
		JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE gm.user_id = $1 AND gm.tenant_id = $2 AND p.key = $3
		ORDER BY via, group_name NULLS FIRST
	`, userID, tenantID, permKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	exp := &Explanation{Paths: []GrantStep{}}
	for rows.Next() {
		var (
			via       string
			groupID   *uuid.UUID
			groupName *string
			roleID    uuid.UUID
			roleName  string
		)
		if err := rows.Scan(&via, &groupID, &groupName, &roleID, &roleName); err != nil {
			return nil, err
		}
		step := GrantStep{
			Permission: permKey,
			GrantedBy:  "role:" + roleName,
			RoleID:     roleID,
		}
		if via == "group" && groupName != nil {
			step.Via = "group:" + *groupName
			step.GroupID = groupID
		} else {
			step.Via = "direct"
		}
		exp.Paths = append(exp.Paths, step)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	exp.Allowed = len(exp.Paths) > 0
	if !exp.Allowed {
		exp.Reason = "no role grants this permission for this user in this tenant"
	}
	return exp, nil
}

// SeedBuiltins ensures the platform permissions + per-tenant default
// roles exist. Idempotent; safe to call on every boot. Manages its own
// transaction since it isn't invoked from an HTTP handler.
func (r *Repository) SeedBuiltins(ctx context.Context) error {
	builtins := []struct{ Key, Desc string }{
		{"tenant.read", "Read tenant configuration"},
		{"tenant.write", "Modify tenant configuration"},
		{"user.read", "List and read users"},
		{"user.write", "Create, update, delete users"},
		{"role.read", "Read roles and assignments"},
		{"role.write", "Manage roles and assignments"},
		{"audit.read", "Read audit events"},
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, b := range builtins {
		if _, err := r.UpsertPermission(ctx, tx, b.Key, b.Desc); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
