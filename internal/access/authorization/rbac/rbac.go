// Package rbac models permissions, per-tenant roles and their assignment to
// users and groups, and enforces route policies (Enforce). Mutating methods
// take a pgx.Tx so the caller commits the change and its audit row together;
// reads use the pool directly.
package rbac

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Permission is a permission key a role can grant, such as "user.read".
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Key         string    `json:"key"`
	Description string    `json:"description"`
}

type permissionDefinition struct{ Key, Description string }

var builtinPermissionDefinitions = []permissionDefinition{
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

// ValidateMachineScopes rejects unknown capabilities at credential issuance.
// vault:<resource> is intentionally dynamic and is rechecked against the path
// by the vault handlers; every other scope must be a built-in permission key.
func ValidateMachineScopes(scopes []string) error {
	known := make(map[string]struct{}, len(builtinPermissionDefinitions))
	for _, permission := range builtinPermissionDefinitions {
		known[permission.Key] = struct{}{}
	}
	for _, scope := range scopes {
		if _, ok := known[scope]; ok {
			continue
		}
		if scope == "vault:read" || (strings.HasPrefix(scope, "vault:") && strings.TrimPrefix(scope, "vault:") != "") {
			continue
		}
		return errs.ErrBadRequest.WithDetail("unknown machine scope: " + scope)
	}
	return nil
}

// Role is a named set of permissions in a tenant.
type Role struct {
	ID          uuid.UUID `json:"id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// Repository reads and writes roles, permissions and role assignments.
type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewRepository returns a Repository over pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an RBAC mutation and its audit row.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// CountCustomRoles returns the number of non-system (custom) roles tenantID
// has defined.
func (r *Repository) CountCustomRoles(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	return r.q.CountCustomRoles(ctx, tenantID)
}

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

// UpsertPermission creates the permission key, or updates its description.
func (r *Repository) UpsertPermission(ctx context.Context, tx pgx.Tx, key, desc string) (*Permission, error) {
	row, err := r.q.WithTx(tx).UpsertPermission(ctx, dbgen.UpsertPermissionParams{Key: key, Description: desc})
	if err != nil {
		return nil, err
	}
	p := toPermission(row)
	return &p, nil
}

// ListPermissions returns every permission key.
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

// CreateRole adds a role to the tenant.
func (r *Repository) CreateRole(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, name, desc string, isSystem bool) (*Role, error) {
	row, err := r.q.WithTx(tx).CreateRole(ctx, dbgen.CreateRoleParams{
		TenantID:    tenantID,
		Name:        name,
		Description: desc,
		IsSystem:    isSystem,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrRBACRoleNameExists
		}
		return nil, err
	}
	role := toRole(row)
	return &role, nil
}

// ListRoles returns the tenant's roles.
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

// RoleTenant returns the tenant a role belongs to, or ErrNotFound. Routes that
// name only a {roleID} use it to keep callers to their own tenant's roles.
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

// ListRolePermissions returns the permissions a role grants.
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

// GrantPermission adds a permission to a role.
func (r *Repository) GrantPermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	return r.q.WithTx(tx).GrantPermission(ctx, dbgen.GrantPermissionParams{RoleID: roleID, PermissionID: permID})
}

// RevokePermission removes a permission from a role.
func (r *Repository) RevokePermission(ctx context.Context, tx pgx.Tx, roleID, permID uuid.UUID) error {
	return r.q.WithTx(tx).RevokePermission(ctx, dbgen.RevokePermissionParams{RoleID: roleID, PermissionID: permID})
}

// AssignRole grants roleID to userID in tenantID; re-assigning is a no-op. The
// INSERT itself requires a role of tenantID and a live member of it, so no
// other tenant's user or role can be attached. Every refusal is
// ErrRBACUserOrRoleNotFound, whichever ID was wrong.
func (r *Repository) AssignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	valid, err := r.q.WithTx(tx).AssignUserRole(ctx, dbgen.AssignUserRoleParams{
		UserID:    userID,
		TenantID:  tenantID,
		RoleID:    roleID,
		GrantedBy: uuidPtrToPgtype(grantedBy),
	})
	if err != nil {
		return err
	}
	if valid == nil || !*valid {
		return errs.ErrRBACUserOrRoleNotFound
	}
	return nil
}

// UnassignRole takes a role away from a user in the tenant.
func (r *Repository) UnassignRole(ctx context.Context, tx pgx.Tx, userID, tenantID, roleID uuid.UUID) error {
	return r.q.WithTx(tx).UnassignUserRole(ctx, dbgen.UnassignUserRoleParams{
		UserID:   userID,
		TenantID: tenantID,
		RoleID:   roleID,
	})
}

// AssignRoleToGroup grants roleID to groupID; re-granting is a no-op. The
// INSERT requires both to belong to tenantID, so no role crosses tenants. It
// reports false, for the caller to answer 404, when the pair isn't valid there.
func (r *Repository) AssignRoleToGroup(ctx context.Context, tx pgx.Tx, groupID, tenantID, roleID uuid.UUID, grantedBy *uuid.UUID) (bool, error) {
	valid, err := r.q.WithTx(tx).AssignRoleToGroup(ctx, dbgen.AssignRoleToGroupParams{
		GroupID:   groupID,
		TenantID:  tenantID,
		RoleID:    roleID,
		GrantedBy: uuidPtrToPgtype(grantedBy),
	})
	if err != nil {
		return false, err
	}
	if valid == nil {
		return false, nil
	}
	return *valid, nil
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

// Check reports whether userID holds a role in tenantID, directly or through a
// group, that grants permKey. Both paths are scoped by tenant_id, so a grant
// never leaks across tenants.
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
	Permission string     `json:"permission"`         // the permission key
	GrantedBy  string     `json:"granted_by"`         // e.g. "role:admin"
	Via        string     `json:"via"`                // "direct" or "group:<name>"
	GroupID    *uuid.UUID `json:"group_id,omitempty"` // the group, when granted through one
	RoleID     uuid.UUID  `json:"role_id"`            // the role that grants it
}

// Explanation is the structured "why?" for a single Check. Allowed is the same
// boolean the hot-path Check returns; Paths lists every distinct grant that
// confers the permission (direct and group-derived), and Reason, with its
// ReasonCode, is set only on a denial.
type Explanation struct {
	Allowed    bool        `json:"allowed"`
	Paths      []GrantStep `json:"paths"`
	Reason     string      `json:"reason,omitempty"`
	ReasonCode string      `json:"reason_code,omitempty"`
}

// ReasonNoRoleGrant is an Explanation's reason code when no role grants the
// permission.
const ReasonNoRoleGrant = "authz.no_role_grant"

// Explain lists every role, direct or through a group, that grants permKey to
// userID in tenantID; Allowed reports whether there is any. Both paths are
// scoped by tenant_id, so a path never names another tenant's grant.
func (r *Repository) Explain(ctx context.Context, userID, tenantID uuid.UUID, permKey string) (*Explanation, error) {
	rows, err := r.q.ExplainGrants(ctx, dbgen.ExplainGrantsParams{
		UserID:   userID,
		TenantID: tenantID,
		PermKey:  permKey,
	})
	if err != nil {
		return nil, err
	}

	exp := &Explanation{Paths: []GrantStep{}}
	for _, row := range rows {
		step := GrantStep{
			Permission: permKey,
			GrantedBy:  "role:" + row.RoleName,
			RoleID:     row.RoleID,
		}
		if row.Via == "group" && row.GroupName != nil {
			step.Via = "group:" + *row.GroupName
			if row.GroupID.Valid {
				gid := uuid.UUID(row.GroupID.Bytes)
				step.GroupID = &gid
			}
		} else {
			step.Via = "direct"
		}
		exp.Paths = append(exp.Paths, step)
	}

	exp.Allowed = len(exp.Paths) > 0
	if !exp.Allowed {
		exp.Reason = "no role grants this permission for this user in this tenant"
		exp.ReasonCode = ReasonNoRoleGrant
	}
	return exp, nil
}

// SeedBuiltins upserts the built-in permissions in its own transaction. It is
// idempotent and safe to run on every boot.
func (r *Repository) SeedBuiltins(ctx context.Context) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, permission := range builtinPermissionDefinitions {
		if _, err := r.UpsertPermission(ctx, tx, permission.Key, permission.Description); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
