package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

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

// toDomain maps a persistence row to the domain Tenant, decoding JSONB metadata
// ([]byte) via the dbutil helper.
func toDomain(row dbgen.TenantTenant) *Tenant {
	return &Tenant{
		ID:        row.ID,
		Slug:      row.Slug,
		Name:      row.Name,
		Status:    row.Status,
		Plan:      row.Plan,
		Region:    row.Region,
		LogoURL:   row.LogoUrl,
		Metadata:  dbutil.Metadata(row.Metadata),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// listRowToTenant maps an enriched list row (tenant columns + the two per-org
// counts) to the domain Tenant. The two ListTenantsForUser* variants generate
// distinct-but-identical row structs, so callers pass the fields positionally.
func listRowToTenant(id uuid.UUID, slug, name, status, plan, region, logoURL string, metadata []byte, createdAt, updatedAt time.Time, memberCount, mfaCount int64) Tenant {
	mc, mfa := memberCount, mfaCount
	return Tenant{
		ID:              id,
		Slug:            slug,
		Name:            name,
		Status:          status,
		Plan:            plan,
		Region:          region,
		LogoURL:         logoURL,
		Metadata:        dbutil.Metadata(metadata),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		MemberCount:     &mc,
		MFAEnabledCount: &mfa,
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

	// InsertTenant and the cross-context writes below are all static SQL, so they run
	// as sqlc queries on the same pgx.Tx via WithTx — one transaction spanning the
	// tenant, rbac, and user bounded contexts.
	q := r.q.WithTx(tx)
	row, err := q.InsertTenant(ctx, dbgen.InsertTenantParams{
		Slug:     strings.TrimSpace(in.Slug),
		Name:     in.Name,
		Plan:     plan,
		Region:   region,
		LogoUrl:  in.LogoURL,
		Metadata: metaJSON,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrOrgSlugTaken
		}
		return nil, err
	}
	t := toDomain(row)

	// Owner role for the tenant, granted every platform permission, then assigned to
	// the owner. These write into other bounded contexts (rbac, user).
	roleID, err := q.InsertOwnerRole(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	if err := q.GrantAllPermissionsToRole(ctx, roleID); err != nil {
		return nil, err
	}
	if err := q.GrantRoleToUser(ctx, dbgen.GrantRoleToUserParams{
		UserID:   ownerID,
		TenantID: t.ID,
		RoleID:   roleID,
	}); err != nil {
		return nil, err
	}
	// Adopt as home tenant only if they have none yet.
	if err := q.AdoptHomeTenant(ctx, dbgen.AdoptHomeTenantParams{
		TenantID: t.ID,
		ID:       ownerID,
	}); err != nil {
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
	out := make([]Tenant, 0, limit+1)
	if cursor == "" {
		rows, err := r.q.ListTenantsForUser(ctx, dbgen.ListTenantsForUserParams{
			UserID: userID,
			Limit:  int32(limit + 1),
		})
		if err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			out = append(out, listRowToTenant(row.ID, row.Slug, row.Name, row.Status, row.Plan,
				row.Region, row.LogoUrl, row.Metadata, row.CreatedAt, row.UpdatedAt,
				row.MemberCount, row.MfaEnabledCount))
		}
	} else {
		curT, curID, perr := paging.DecodeTimeUUID(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err := r.q.ListTenantsForUserAfter(ctx, dbgen.ListTenantsForUserAfterParams{
			UserID:          userID,
			BeforeCreatedAt: curT,
			BeforeID:        curID,
			RowLimit:        int32(limit + 1),
		})
		if err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			out = append(out, listRowToTenant(row.ID, row.Slug, row.Name, row.Status, row.Plan,
				row.Region, row.LogoUrl, row.Metadata, row.CreatedAt, row.UpdatedAt,
				row.MemberCount, row.MfaEnabledCount))
		}
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
	// plan is deliberately not settable here — it's owned by billing (see UpdateInput).
	if in.Region != nil {
		ub.Set("region", *in.Region)
	}
	if in.LogoURL != nil {
		ub.Set("logo_url", *in.LogoURL)
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
		&rec.Region, &rec.LogoUrl, &rec.Metadata, &rec.CreatedAt, &rec.UpdatedAt); err != nil {
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
const tenantCols = `id, slug, name, status, plan, region, logo_url, metadata, created_at, updated_at`

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

// IsEmailVerified reports whether the user has a verified email — the gate for
// self-serve org creation.
func (r *Repository) IsEmailVerified(ctx context.Context, userID uuid.UUID) (bool, error) {
	return r.q.IsEmailVerified(ctx, userID)
}
