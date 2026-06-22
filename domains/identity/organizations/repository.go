package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/dbutil"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/paging"
	"github.com/qeetgroup/qeet-id/platform/pgxerr"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

func scanTenant(row pgx.Row) (*Tenant, error) {
	var t Tenant
	var meta []byte
	if err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Plan, &t.Region, &meta, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	t.Metadata = dbutil.Metadata(meta)
	return &t, nil
}

const tenantCols = `id, slug, name, status, plan, region, metadata, created_at, updated_at`

// CreateWithOwner creates a tenant and, in one tx, makes ownerID its owner (owner role + permissions + membership + home tenant).
func (r *Repository) CreateWithOwner(ctx context.Context, in CreateInput, ownerID uuid.UUID) (*Tenant, error) {
	plan := in.Plan
	if plan == "" {
		plan = "free"
	}
	region := in.Region
	if region == "" {
		region = "us-east-1"
	}
	meta := in.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		INSERT INTO tenant.tenants (slug, name, plan, region, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+tenantCols,
		strings.TrimSpace(in.Slug), in.Name, plan, region, metaJSON,
	)
	t, err := scanTenant(row)
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("slug already exists")
		}
		return nil, err
	}

	// Owner role for the tenant, granted every platform permission.
	var roleID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, description, is_system)
		VALUES ($1, 'owner', 'Tenant owner — full access', TRUE)
		RETURNING id
	`, t.ID).Scan(&roleID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rbac.role_permissions (role_id, permission_id)
		SELECT $1, id FROM rbac.permissions
	`, roleID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rbac.user_roles (user_id, tenant_id, role_id, granted_by)
		VALUES ($1, $2, $3, $1)
	`, ownerID, t.ID, roleID); err != nil {
		return nil, err
	}
	// Adopt as home tenant only if they have none yet.
	if _, err := tx.Exec(ctx, `
		UPDATE "user".users SET tenant_id = $1, updated_at = NOW()
		WHERE id = $2 AND tenant_id IS NULL AND deleted_at IS NULL
	`, t.ID, ownerID); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+tenantCols+`
		FROM tenant.tenants
		WHERE id = $1 AND deleted_at IS NULL
	`, id)
	return scanTenant(row)
}

func (r *Repository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+tenantCols+`
		FROM tenant.tenants
		WHERE LOWER(slug) = LOWER($1) AND deleted_at IS NULL
	`, slug)
	return scanTenant(row)
}

// List returns the tenants the user is a member of (scoped to the caller), newest first.
func (r *Repository) List(ctx context.Context, userID uuid.UUID, limit int, cursor string) ([]Tenant, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var (
		rows pgx.Rows
		err  error
	)
	if cursor == "" {
		rows, err = r.pool.Query(ctx, `
			SELECT `+tenantCols+`
			FROM tenant.tenants
			WHERE deleted_at IS NULL
			  AND EXISTS (
				SELECT 1 FROM rbac.user_roles ur
				WHERE ur.tenant_id = tenant.tenants.id AND ur.user_id = $1
			  )
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, userID, limit+1)
	} else {
		curT, curID, perr := paging.DecodeTimeUUID(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err = r.pool.Query(ctx, `
			SELECT `+tenantCols+`
			FROM tenant.tenants
			WHERE deleted_at IS NULL
			  AND EXISTS (
				SELECT 1 FROM rbac.user_roles ur
				WHERE ur.tenant_id = tenant.tenants.id AND ur.user_id = $1
			  )
			  AND (created_at, id) < ($2, $3)
			ORDER BY created_at DESC, id DESC
			LIMIT $4
		`, userID, curT, curID, limit+1)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []Tenant
	for rows.Next() {
		var t Tenant
		var meta []byte
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Plan, &t.Region, &meta, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, "", err
		}
		t.Metadata = dbutil.Metadata(meta)
		out = append(out, t)
	}
	var next string
	if len(out) > limit {
		last := out[limit-1]
		next = paging.EncodeTimeUUID(last.CreatedAt, last.ID)
		out = out[:limit]
	}
	return out, next, nil
}

func (r *Repository) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	ub := dbutil.NewUpdate()
	if in.Name != nil {
		ub.Set("name", *in.Name)
	}
	if in.Status != nil {
		ub.Set("status", *in.Status)
	}
	if in.Plan != nil {
		ub.Set("plan", *in.Plan)
	}
	if in.Region != nil {
		ub.Set("region", *in.Region)
	}
	if in.Metadata != nil {
		meta, err := json.Marshal(in.Metadata)
		if err != nil {
			return nil, err
		}
		ub.Set("metadata", meta)
	}
	if ub.Empty() {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return r.Get(ctx, id)
	}
	ub.SetRaw("updated_at = NOW()")
	idAt := ub.NextPlaceholder()
	args := append(ub.Args(), id)
	q := `UPDATE tenant.tenants SET ` + ub.Assignments() +
		` WHERE id = $` + strconv.Itoa(idAt) + ` AND deleted_at IS NULL RETURNING ` + tenantCols
	row := tx.QueryRow(ctx, q, args...)
	t, err := scanTenant(row)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE tenant.tenants
		SET deleted_at = NOW(), status = 'deleted', updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}
