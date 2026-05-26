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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
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

// Check returns true if the user holds any role in tenant that grants
// the named permission.
func (r *Repository) Check(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (bool, error) {
	var ok bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM rbac.user_roles ur
			JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
			JOIN rbac.permissions p ON p.id = rp.permission_id
			WHERE ur.user_id = $1 AND ur.tenant_id = $2 AND p.key = $3
		)
	`, userID, tenantID, permKey).Scan(&ok)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	return ok, nil
}

// EffectivePermissions returns all permission keys granted to a user
// within a tenant via any of their roles.
func (r *Repository) EffectivePermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT p.key
		FROM rbac.user_roles ur
		JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
		JOIN rbac.permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
		ORDER BY p.key
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
