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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/dbutil"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Repository reads and writes organisations.
type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewRepository returns a Repository over pool.
func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// toDomain maps a persistence row to the domain Tenant, decoding JSONB metadata
// ([]byte) via the dbutil helper.
func toDomain(row dbgen.TenantTenant) *Tenant {
	return &Tenant{
		ID:            row.ID,
		Slug:          row.Slug,
		Name:          row.Name,
		Status:        row.Status,
		Plan:          row.Plan,
		Region:        row.Region,
		LogoURL:       row.LogoUrl,
		Metadata:      dbutil.Metadata(row.Metadata),
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		DeletionDueAt: timeOrNil(row.DeletionDueAt),
	}
}

// timeOrNil is t's time, or nil when t is NULL.
func timeOrNil(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// listRowToTenant maps an enriched list row (tenant columns + the two per-org
// counts) to the domain Tenant. The two ListTenantsForUser* variants generate
// distinct-but-identical row structs, so callers pass the fields positionally.
func listRowToTenant(id uuid.UUID, slug, name, status, plan, region, logoURL string, metadata []byte, createdAt, updatedAt time.Time, deletionDueAt pgtype.Timestamptz, memberCount, mfaCount int64) Tenant {
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
		DeletionDueAt:   timeOrNil(deletionDueAt),
		MemberCount:     &mc,
		MFAEnabledCount: &mfa,
	}
}

// CreateWithOwner creates a tenant and, in one tx, makes ownerID its owner (owner role + permissions + membership + home tenant).
func (r *Repository) CreateWithOwner(ctx context.Context, in CreateInput, ownerID uuid.UUID) (*Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tenant, err := r.CreateWithOwnerTx(ctx, tx, in, ownerID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return tenant, nil
}

// CreateWithOwnerTx creates the tenant, owner role, permission grants,
// membership, and home-tenant assignment in the caller's transaction.
func (r *Repository) CreateWithOwnerTx(ctx context.Context, tx pgx.Tx, in CreateInput, ownerID uuid.UUID) (*Tenant, error) {
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

	return t, nil
}

// Get returns an organisation by id.
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

// GetBySlug returns an organisation by its slug.
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
				row.DeletionDueAt, row.MemberCount, row.MfaEnabledCount))
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
				row.DeletionDueAt, row.MemberCount, row.MfaEnabledCount))
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

// StatusChange runs inside the transaction that changes an organisation's
// status, so the change and what follows from it — its sessions ended, the
// audit row, the event — commit together or not at all.
type StatusChange func(ctx context.Context, tx pgx.Tx, from, to string) error

// Update applies the non-nil fields of in to tenant id. The SET clause is built
// at run time, so this is hand-written rather than sqlc. When the status
// changes, onStatus (if non-nil) runs in the same transaction.
func (r *Repository) Update(ctx context.Context, id uuid.UUID, in UpdateInput, onStatus StatusChange) (*Tenant, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var from string
	if in.Status != nil {
		if err := tx.QueryRow(ctx, `SELECT status FROM tenant.tenants WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).
			Scan(&from); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errs.ErrNotFound
			}
			return nil, err
		}
	}

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
	if in.Status != nil && *in.Status != from && onStatus != nil {
		if err := onStatus(ctx, tx, from, *in.Status); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return toDomain(rec), nil
}

// tenantCols is the column list for the hand-written Update RETURNING clause;
// it matches the field order scanned into dbgen.TenantTenant above (sans deleted_at).
const tenantCols = `id, slug, name, status, plan, region, logo_url, metadata, created_at, updated_at`

// SoftDelete deletes the organisation (its rows stay, marked deleted).
// onDeleted (nil: none) runs in the same transaction, given the status it had.
func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID, onDeleted StatusChange) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var from string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenant.tenants WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, id).
		Scan(&from); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrNotFound
		}
		return err
	}
	if _, err := r.q.WithTx(tx).SoftDeleteTenant(ctx, id); err != nil {
		return err
	}
	if onDeleted != nil {
		if err := onDeleted(ctx, tx, from, "deleted"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DeletionGrace is how long a scheduled deletion waits, during which an owner
// can call it off.
const DeletionGrace = 7 * 24 * time.Hour

// ScheduleDeletion schedules tenant id's deletion DeletionGrace from now and
// runs onScheduled in the same transaction; it returns when the deletion is
// due. ErrTenantDeletionScheduled when one already is; ErrNotFound when the
// tenant is gone.
func (r *Repository) ScheduleDeletion(ctx context.Context, id uuid.UUID, onScheduled func(ctx context.Context, tx pgx.Tx, due time.Time) error) (time.Time, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	due, err := r.q.WithTx(tx).ScheduleTenantDeletion(ctx, dbgen.ScheduleTenantDeletionParams{ID: id, DueAt: time.Now().UTC().Add(DeletionGrace)})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := r.q.WithTx(tx).GetTenant(ctx, id); errors.Is(gerr, pgx.ErrNoRows) {
			return time.Time{}, errs.ErrNotFound
		}
		return time.Time{}, errs.ErrTenantDeletionScheduled
	}
	if err != nil {
		return time.Time{}, err
	}
	if onScheduled != nil {
		if err := onScheduled(ctx, tx, due.Time); err != nil {
			return time.Time{}, err
		}
	}
	return due.Time, tx.Commit(ctx)
}

// CancelDeletion calls off tenant id's scheduled deletion and runs
// onCancelled in the same transaction. ErrTenantDeletionNotScheduled when
// none is.
func (r *Repository) CancelDeletion(ctx context.Context, id uuid.UUID, onCancelled func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := r.q.WithTx(tx).CancelTenantDeletion(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrTenantDeletionNotScheduled
	}
	if onCancelled != nil {
		if err := onCancelled(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DueForDeletion lists up to maxRows organisations whose scheduled deletion
// is due. It reads every organisation, for the background job.
func (r *Repository) DueForDeletion(ctx context.Context, maxRows int32) ([]uuid.UUID, error) {
	return r.q.ListTenantsDueForDeletion(ctx, maxRows)
}

// IsEmailVerified reports whether the user has a verified email — the gate for
// self-serve org creation.
func (r *Repository) IsEmailVerified(ctx context.Context, userID uuid.UUID) (bool, error) {
	return r.q.IsEmailVerified(ctx, userID)
}
