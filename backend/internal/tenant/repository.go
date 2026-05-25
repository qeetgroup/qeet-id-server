package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
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
	if len(meta) > 0 {
		_ = json.Unmarshal(meta, &t.Metadata)
	}
	if t.Metadata == nil {
		t.Metadata = map[string]any{}
	}
	return &t, nil
}

const tenantCols = `id, slug, name, status, plan, region, metadata, created_at, updated_at`

func (r *Repository) Create(ctx context.Context, in CreateInput) (*Tenant, error) {
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, errs.ErrConflict.WithDetail("slug already exists")
		}
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

func (r *Repository) List(ctx context.Context, limit int, cursor string) ([]Tenant, string, error) {
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
			ORDER BY created_at DESC, id DESC
			LIMIT $1
		`, limit+1)
	} else {
		cur, perr := uuid.Parse(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err = r.pool.Query(ctx, `
			SELECT `+tenantCols+`
			FROM tenant.tenants
			WHERE deleted_at IS NULL
			  AND (created_at, id) <
			      (SELECT created_at, id FROM tenant.tenants WHERE id = $1)
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, cur, limit+1)
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
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &t.Metadata)
		}
		if t.Metadata == nil {
			t.Metadata = map[string]any{}
		}
		out = append(out, t)
	}
	var next string
	if len(out) > limit {
		next = out[limit].ID.String()
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

	var (
		sets []string
		args []any
		i    = 1
	)
	if in.Name != nil {
		sets = append(sets, "name = $"+strconv.Itoa(i))
		args = append(args, *in.Name)
		i++
	}
	if in.Status != nil {
		sets = append(sets, "status = $"+strconv.Itoa(i))
		args = append(args, *in.Status)
		i++
	}
	if in.Plan != nil {
		sets = append(sets, "plan = $"+strconv.Itoa(i))
		args = append(args, *in.Plan)
		i++
	}
	if in.Region != nil {
		sets = append(sets, "region = $"+strconv.Itoa(i))
		args = append(args, *in.Region)
		i++
	}
	if in.Metadata != nil {
		meta, _ := json.Marshal(in.Metadata)
		sets = append(sets, "metadata = $"+strconv.Itoa(i))
		args = append(args, meta)
		i++
	}
	if len(sets) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return r.Get(ctx, id)
	}
	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	q := `UPDATE tenant.tenants SET ` + strings.Join(sets, ", ") +
		` WHERE id = $` + strconv.Itoa(i) + ` AND deleted_at IS NULL RETURNING ` + tenantCols
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

