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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
	q    *dbgen.Queries
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an RBAC mutation and its audit row.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// toPermission maps a generated RbacPermission row to the domain Permission type.
func toPermission(row dbgen.RbacPermission) Permission {
	return Permission{ID: row.ID, Key: row.Key, Description: row.Description}
}

// toRole maps a generated RbacRole row to the domain Role type.
func toRole(row dbgen.RbacRole) Role {
	return Role{
		ID:          row.ID,
		TenantID:    row.TenantID,
		Name:        row.Name,
		Description: row.Description,
		IsSystem:    row.IsSystem,
		CreatedAt:   row.CreatedAt,
	}
}

// uuidPtrToPgtype converts a *uuid.UUID to pgtype.UUID for nullable UUID params.
func uuidPtrToPgtype(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}

func (r *Repository) UpsertPermission(ctx context.Context, tx pgx.Tx, key, desc string) (*Permission, error) {
	row, err := r.q.WithTx(tx).UpsertPermission(ctx, dbgen.UpsertPermissionParams{Key: key, Description: desc})
	if err != nil {
		return nil, err
	}
	p := toPermission(row)
	return &p, nil
}

func (r *Repository) ListPermissions(ctx context.Context) ([]Permission, error) {
	rows, err := r.q.ListPermissions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Permission, len(rows))
	for i, row := range rows {
		out[i] = toPermission(row)
	}
	return out, nil
}

func (r *Repository) CreateRole(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, name, desc string, isSystem bool) (*Role, error) {
	row, err := r.q.WithTx(tx).CreateRole(ctx, dbgen.CreateRoleParams{
		TenantID:    tenantID,
		Name:        name,
		Description: desc,
		IsSystem:    isSystem,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("role name exists for tenant")
		}
		return nil, err
	}
	role := toRole(row)
	return &role, nil
}

func (r *Repository) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]Role, error) {
	rows, err := r.q.ListRoles(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Role, len(rows))
	for i, row := range rows {
		out[i] = toRole(row)
	}
	return out, nil
}

// RoleTenant returns the tenant a role belongs to, or ErrNotFound. The
// role-permission routes carry only a {roleID} (no {tenantID}), so handlers use
// this to enforce the role belongs to the caller's own tenant (QID-18).
func (r *Repository) RoleTenant(ctx context.Context, roleID uuid.UUID) (uuid.UUID, error) {
	tid, err := r.q.GetRoleTenant(ctx, roleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return tid, nil
}

func (r *Repository) ListRolePermissions(ctx context.Context, roleID uuid.UUID) ([]Permission, error) {
	rows, err := r.q.ListRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	out := make([]Permission, len(rows))
	for i, row := range rows {
		out[i] = toPermission(row)
	}
	return out, nil
}

func (r *Repository) GrantPermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	return r.q.WithTx(tx).GrantPermission(ctx, dbgen.GrantPermissionParams{RoleID: roleID, PermissionID: permID})
}

func (r *Repository) RevokePermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	return r.q.WithTx(tx).RevokePermission(ctx, dbgen.RevokePermissionParams{RoleID: roleID, PermissionID: permID})
}

func (r *Repository) AssignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	return r.q.WithTx(tx).AssignUserRole(ctx, dbgen.AssignUserRoleParams{
		UserID:    userID,
		TenantID:  tenantID,
		RoleID:    roleID,
		GrantedBy: uuidPtrToPgtype(grantedBy),
	})
}

func (r *Repository) UnassignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID) error {
	return r.q.WithTx(tx).UnassignUserRole(ctx, dbgen.UnassignUserRoleParams{
		UserID:   userID,
		TenantID: tenantID,
		RoleID:   roleID,
	})
}

// AssignRoleToGroup grants a role to a group. The role and the group must both
// belong to tenantID; we enforce that in the INSERT's SELECT so a caller can
// never bind a role from one tenant to a group in another. ON CONFLICT keeps it
// idempotent. The returned bool reports whether the role/group pair was valid
// for this tenant (false => the caller should surface a 404), distinguishing a
// genuine no-op from a cross-tenant or missing-row attempt.
//
// Left as raw SQL: the conditional CTE (INSERT … SELECT … WHERE EXISTS) is not
// cleanly modelled by sqlc — the RETURNING 1 constant expression and the wrapping
// SELECT EXISTS(FROM ins) OR EXISTS(…) don't map to a standard result type.
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
	return r.q.WithTx(tx).RemoveRoleFromGroup(ctx, dbgen.RemoveRoleFromGroupParams{
		GroupID:  groupID,
		TenantID: tenantID,
		RoleID:   roleID,
	})
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
	rows, err := r.q.ListGroupRoles(ctx, dbgen.ListGroupRolesParams{GroupID: groupID, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	out := make([]GroupRole, len(rows))
	for i, row := range rows {
		out[i] = GroupRole{RoleID: row.RoleID, Name: row.Name, GrantedAt: row.GrantedAt}
	}
	return out, nil
}

// Check returns true if the user holds any role in tenant that grants the
// named permission — counting BOTH roles granted directly to the user and
// roles granted to a group the user belongs to. The two arms are scoped by
// tenant_id independently so a grant can never leak across tenants.
func (r *Repository) Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error) {
	ok, err := r.q.CheckPermission(ctx, dbgen.CheckPermissionParams{
		UserID:   userID,
		TenantID: tenantID,
		PermKey:  permKey,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return ok, nil
}

// EffectivePermissions returns all permission keys granted to a user within a
// tenant — via roles granted directly to the user UNION roles granted to any
// group the user belongs to.
func (r *Repository) EffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	return r.q.ListEffectivePermissions(ctx, dbgen.ListEffectivePermissionsParams{
		UserID:   userID,
		TenantID: tenantID,
	})
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
//
// Left as raw SQL: the two-armed UNION ALL uses typed NULL literals
// ('direct'::text, NULL::uuid, NULL::text) whose nullable-expression types
// can't be expressed through the sqlc override configuration without additional
// column-level overrides that would complicate the config.
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
		{"user.write", "Create, update, delete users (incl. set password, reset MFA)"},
		{"role.read", "Read roles and assignments"},
		{"role.write", "Manage roles and assignments"},
		{"audit.read", "Read audit events"},
		{"audit.write", "Resolve audit anomalies and manage anomaly-detection settings"},
		{"group.read", "Read groups and members"},
		{"group.write", "Manage groups and members"},
		{"connection.read", "Read SSO/identity connections (OIDC, SAML, SCIM, LDAP, social)"},
		{"connection.write", "Manage SSO/identity connections"},
		{"apikey.read", "Read API keys and service principals"},
		{"apikey.write", "Manage API keys and service principals"},
		{"secret.read", "Read tenant secrets metadata"},
		{"secret.write", "Manage tenant secrets"},
		{"webhook.read", "Read webhook endpoints"},
		{"webhook.write", "Manage webhook endpoints"},
		{"billing.read", "Read billing plans and subscription"},
		{"billing.write", "Manage billing subscription"},
		{"branding.write", "Manage hosted-login branding and email templates"},
		{"policy.read", "Read security/auth policy"},
		{"policy.write", "Manage security/auth policy (password, IP rules, retention, MFA enforcement)"},
		{"gdpr.write", "Run GDPR erasure / data operations"},
		{"analytics.read", "Read tenant analytics"},
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
