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

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/dbutil"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// toDomain maps a generated persistence row to the domain Tenant model.
// JSONB metadata ([]byte) is decoded here via the existing dbutil helper, so the
// domain Tenant type (and its callers) are unchanged.
func toDomain(row dbgen.TenantTenant) *Tenant {
	return &Tenant{
		ID:        row.ID,
		Slug:      row.Slug,
		Name:      row.Name,
		Status:    row.Status,
		Plan:      row.Plan,
		Region:    row.Region,
		Metadata:  dbutil.Metadata(row.Metadata),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

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

	// The sqlc-generated query and the raw cross-context statements below all run
	// on the same pgx.Tx — sqlc queries and hand-written SQL compose in one transaction.
	row, err := r.q.WithTx(tx).InsertTenant(ctx, dbgen.InsertTenantParams{
		Slug:     strings.TrimSpace(in.Slug),
		Name:     in.Name,
		Plan:     plan,
		Region:   region,
		Metadata: metaJSON,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.WithDetail("slug already exists")
		}
		return nil, err
	}
	t := toDomain(row)

	// Owner role for the tenant, granted every platform permission. These write into
	// other bounded contexts (rbac, user), so they stay hand-written on the shared tx.
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
	row, err := r.q.GetTenant(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

func (r *Repository) GetBySlug(ctx context.Context, slug string) (*Tenant, error) {
	row, err := r.q.GetTenantBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

// List returns the tenants the user is a member of (scoped to the caller), newest first.
func (r *Repository) List(ctx context.Context, userID uuid.UUID, limit int, cursor string) ([]Tenant, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var (
		rows []dbgen.TenantTenant
		err  error
	)
	if cursor == "" {
		rows, err = r.q.ListTenantsForUser(ctx, dbgen.ListTenantsForUserParams{
			UserID: userID,
			Limit:  int32(limit + 1),
		})
	} else {
		curT, curID, perr := paging.DecodeTimeUUID(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err = r.q.ListTenantsForUserAfter(ctx, dbgen.ListTenantsForUserAfterParams{
			UserID:          userID,
			BeforeCreatedAt: curT,
			BeforeID:        curID,
			RowLimit:        int32(limit + 1),
		})
	}
	if err != nil {
		return nil, "", err
	}

	out := make([]Tenant, 0, len(rows))
	for _, row := range rows {
		out = append(out, *toDomain(row))
	}
	var next string
	if len(out) > limit {
		last := out[limit-1]
		next = paging.EncodeTimeUUID(last.CreatedAt, last.ID)
		out = out[:limit]
	}
	return out, next, nil
}

// Update applies a partial update. The SET clause is built dynamically from the
// non-nil fields, so it intentionally stays hand-written (sqlc has no good story
// for optional-column updates); it shares the domain's error/RETURNING conventions.
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
	var rec dbgen.TenantTenant
	if err := row.Scan(&rec.ID, &rec.Slug, &rec.Name, &rec.Status, &rec.Plan,
		&rec.Region, &rec.Metadata, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return toDomain(rec), nil
}

// tenantCols is the column list for the hand-written Update RETURNING clause;
// it matches the field order scanned into dbgen.TenantTenant above (sans deleted_at).
const tenantCols = `id, slug, name, status, plan, region, metadata, created_at, updated_at`

func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.SoftDeleteTenant(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}
