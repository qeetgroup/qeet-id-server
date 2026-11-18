package organization

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// toDomain maps a persistence row to the domain Organization, decoding JSONB metadata
// ([]byte) via the dbutil helper.
func toDomain(row dbgen.OrganizationOrganization) *Organization {
	return &Organization{
		ID:            row.ID,
		Slug:          row.Slug,
		Name:          row.Name,
		Status:        row.Status,
		Plan:          row.Plan,
		Region:        row.Region,
		LogoURL:       row.LogoUrl,
		Metadata:      postgres.Metadata(row.Metadata),
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		DeletionDueAt: row.DeletionDueAt,
	}
}

// listRowToOrganization maps an enriched list row (organization columns + the two per-org
// counts) to the domain Organization. The two ListOrganizationsForUser* variants generate
// distinct-but-identical row structs, so callers pass the fields positionally.
func listRowToOrganization(id uuid.UUID, slug, name, status, plan, region, logoURL string, metadata []byte, createdAt, updatedAt time.Time, deletionDueAt *time.Time, memberCount, mfaCount int64) Organization {
	mc, mfa := memberCount, mfaCount
	return Organization{
		ID:              id,
		Slug:            slug,
		Name:            name,
		Status:          status,
		Plan:            plan,
		Region:          region,
		LogoURL:         logoURL,
		Metadata:        postgres.Metadata(metadata),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
		DeletionDueAt:   deletionDueAt,
		MemberCount:     &mc,
		MFAEnabledCount: &mfa,
	}
}

// CreateWithOwner creates an organization and, in one tx, makes ownerID its owner (owner role + permissions + membership + home organization).
func (r *Repository) CreateWithOwner(ctx context.Context, in CreateInput, ownerID uuid.UUID) (*Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	organization, err := r.createWithOwner(ctx, tx, in, ownerID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return organization, nil
}

// Create is CreateWithOwner for an organization actor creates: the
// organization.created audit row and event commit with it.
func (r *Repository) Create(ctx context.Context, in CreateInput, ownerID uuid.UUID, actor audit.Actor) (*Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	t, err := r.createWithOwner(ctx, tx, in, ownerID)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(t.ID, "organization.created", "organization", t.ID,
		map[string]any{"slug": t.Slug, "name": t.Name})); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: t.ID, Topic: "organization.events", EventType: "organization.created", Payload: t,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

// createWithOwner creates the organization, owner role, permission grants,
// membership, and home-organization assignment in tx.
func (r *Repository) createWithOwner(ctx context.Context, tx pgx.Tx, in CreateInput, ownerID uuid.UUID) (*Organization, error) {
	plan := in.Plan
	if plan == "" {
		plan = "free"
	}
	// The deployment's region whatever was asked: a request for another is
	// refused where it is made (create), and one already paid for at sign-up
	// is still provisioned.
	region := r.HostingRegion()
	meta := in.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	// InsertOrganization and the cross-context writes below are all static SQL, so they run
	// as sqlc queries on the same pgx.Tx via WithTx — one transaction spanning the
	// organization, rbac, and user bounded contexts.
	q := r.q.WithTx(tx)
	row, err := q.InsertOrganization(ctx, dbgen.InsertOrganizationParams{
		Slug:     strings.TrimSpace(in.Slug),
		Name:     in.Name,
		Plan:     plan,
		Region:   region,
		LogoUrl:  in.LogoURL,
		Metadata: metaJSON,
	})
	if err != nil {
		if postgres.IsUnique(err) {
			return nil, errs.ErrOrgSlugTaken
		}
		return nil, err
	}
	t := toDomain(row)

	// Owner role for the organization, granted every platform permission, then assigned to
	// the owner. These write into other bounded contexts (rbac, user).
	roleID, err := q.InsertOwnerRole(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	if err := q.GrantAllPermissionsToRole(ctx, roleID); err != nil {
		return nil, err
	}
	if err := q.InsertBuiltinRoles(ctx, t.ID); err != nil {
		return nil, err
	}
	if err := q.GrantRoleToUser(ctx, dbgen.GrantRoleToUserParams{
		UserID:         ownerID,
		OrganizationID: t.ID,
		RoleID:         roleID,
	}); err != nil {
		return nil, err
	}
	// Adopt as home organization only if they have none yet.
	if err := q.AdoptHomeOrganization(ctx, dbgen.AdoptHomeOrganizationParams{
		OrganizationID: t.ID,
		ID:             ownerID,
	}); err != nil {
		return nil, err
	}

	return t, nil
}

// Get returns an organization by id.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*Organization, error) {
	row, err := r.q.GetOrganization(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

// GetBySlug returns an organization by its slug.
func (r *Repository) GetBySlug(ctx context.Context, slug string) (*Organization, error) {
	row, err := r.q.GetOrganizationBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return toDomain(row), nil
}

// The page sizes of List: by default, and at most.
const (
	listLimit    = 50
	listMaxLimit = 200
)

// List returns a page of the organizations the user is a member of (scoped to
// the caller), newest first, after the cursor when one is set, and the next
// page's cursor: empty on the last page.
func (r *Repository) List(ctx context.Context, userID uuid.UUID, limit int, after paging.Cursor) ([]Organization, string, error) {
	limit = paging.Clamp(limit, listLimit, listMaxLimit)
	out := make([]Organization, 0, limit+1)
	if !after.Set {
		rows, err := r.q.ListOrganizationsForUser(ctx, dbgen.ListOrganizationsForUserParams{
			UserID: userID,
			Limit:  int32(limit + 1), // #nosec G115 -- clamped to at most listMaxLimit
		})
		if err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			out = append(out, listRowToOrganization(row.ID, row.Slug, row.Name, row.Status, row.Plan,
				row.Region, row.LogoUrl, row.Metadata, row.CreatedAt, row.UpdatedAt,
				row.DeletionDueAt, row.MemberCount, row.MfaEnabledCount))
		}
	} else {
		rows, err := r.q.ListOrganizationsForUserAfter(ctx, dbgen.ListOrganizationsForUserAfterParams{
			UserID:          userID,
			BeforeCreatedAt: after.Time,
			BeforeID:        after.ID,
			RowLimit:        int32(limit + 1), // #nosec G115 -- clamped to at most listMaxLimit
		})
		if err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			out = append(out, listRowToOrganization(row.ID, row.Slug, row.Name, row.Status, row.Plan,
				row.Region, row.LogoUrl, row.Metadata, row.CreatedAt, row.UpdatedAt,
				row.DeletionDueAt, row.MemberCount, row.MfaEnabledCount))
		}
	}
	out, next := paging.Next(out, limit, func(o Organization) (time.Time, uuid.UUID) { return o.CreatedAt, o.ID })
	return out, next, nil
}

// StatusChange runs inside the transaction that changes an organization's
// status, so the change and what follows from it — its sessions ended, the
// audit row, the event — commit together or not at all.
type StatusChange func(ctx context.Context, tx pgx.Tx, from, to string) error

// Changed runs inside the transaction that updates an organization, given it
// before and after the update, so what records the change commits with it.
type Changed func(ctx context.Context, tx pgx.Tx, before, after *Organization) error

// Update applies the non-nil fields of in to organization id. The SET clause is built
// at run time, so this is hand-written rather than sqlc. In the same
// transaction onChange (if non-nil) runs after any update, and onStatus (if
// non-nil) when the status changes.
func (r *Repository) Update(ctx context.Context, id uuid.UUID, in UpdateInput, onStatus StatusChange, onChange Changed) (*Organization, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	ub := postgres.NewUpdate()
	if in.Name != nil {
		ub.Set("name", *in.Name)
	}
	if in.Status != nil {
		ub.Set("status", *in.Status)
	}
	// plan is deliberately not settable here — it's owned by billing (see UpdateInput).
	// Nor is the region, the deployment's: the same one again is accepted, as a
	// form sends every field back.
	q := r.q.WithTx(tx)
	if in.Region != nil {
		current, err := q.GetOrganizationRegion(ctx, id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if *in.Region != current {
			return nil, ErrRegionReadOnly
		}
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
	old, err := q.LockOrganization(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ub.SetRaw("updated_at = NOW()")
	idAt := ub.NextPlaceholder()
	args := append(ub.Args(), id)
	update := `UPDATE organization.organizations SET ` + ub.Assignments() +
		` WHERE id = $` + strconv.Itoa(idAt) + ` AND deleted_at IS NULL RETURNING ` + organizationCols
	rec, err := scanOrganization(tx.QueryRow(ctx, update, args...))
	if err != nil {
		return nil, err
	}
	before, after := toDomain(old), toDomain(rec)
	if onChange != nil {
		if err := onChange(ctx, tx, before, after); err != nil {
			return nil, err
		}
	}
	if in.Status != nil && *in.Status != before.Status && onStatus != nil {
		if err := onStatus(ctx, tx, before.Status, *in.Status); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return after, nil
}

// organizationCols is the column list Update's hand-written UPDATE returns, in
// the order scanOrganization reads it (dbgen.OrganizationOrganization without deleted_at).
const organizationCols = `id, slug, name, status, plan, region, logo_url, metadata, created_at, updated_at, deletion_due_at`

// scanOrganization reads a row of organizationCols; ErrNotFound for none.
func scanOrganization(row pgx.Row) (dbgen.OrganizationOrganization, error) {
	var rec dbgen.OrganizationOrganization
	err := row.Scan(&rec.ID, &rec.Slug, &rec.Name, &rec.Status, &rec.Plan,
		&rec.Region, &rec.LogoUrl, &rec.Metadata, &rec.CreatedAt, &rec.UpdatedAt, &rec.DeletionDueAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, errs.ErrNotFound
	}
	return rec, err
}

// SoftDelete deletes the organization (its rows stay, marked deleted).
// onDeleted (nil: none) runs in the same transaction, given the status it had.
func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID, onDeleted StatusChange) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	from, err := r.q.WithTx(tx).LockOrganizationStatus(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := r.q.WithTx(tx).SoftDeleteOrganization(ctx, id); err != nil {
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

// ScheduleDeletion schedules organization id's deletion DeletionGrace from now and
// runs onScheduled in the same transaction; it returns when the deletion is
// due. ErrOrganizationDeletionScheduled when one already is; ErrNotFound when the
// organization is gone.
func (r *Repository) ScheduleDeletion(ctx context.Context, id uuid.UUID, onScheduled func(ctx context.Context, tx pgx.Tx, due time.Time) error) (time.Time, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	due, err := r.q.WithTx(tx).ScheduleOrganizationDeletion(ctx, dbgen.ScheduleOrganizationDeletionParams{ID: id, DueAt: time.Now().UTC().Add(DeletionGrace)})
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := r.q.WithTx(tx).GetOrganization(ctx, id); errors.Is(gerr, pgx.ErrNoRows) {
			return time.Time{}, errs.ErrNotFound
		}
		return time.Time{}, ErrDeletionScheduled
	}
	if err != nil {
		return time.Time{}, err
	}
	if onScheduled != nil {
		if err := onScheduled(ctx, tx, postgres.ZeroIfNull(due)); err != nil {
			return time.Time{}, err
		}
	}
	return postgres.ZeroIfNull(due), tx.Commit(ctx)
}

// CancelDeletion calls off organization id's scheduled deletion and runs
// onCancelled in the same transaction. ErrOrganizationDeletionNotScheduled when
// none is.
func (r *Repository) CancelDeletion(ctx context.Context, id uuid.UUID, onCancelled func(ctx context.Context, tx pgx.Tx) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := r.q.WithTx(tx).CancelOrganizationDeletion(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDeletionNotScheduled
	}
	if onCancelled != nil {
		if err := onCancelled(ctx, tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// DueForDeletion lists up to maxRows organizations whose scheduled deletion
// is due. It reads every organization, for the background job.
func (r *Repository) DueForDeletion(ctx context.Context, maxRows int32) ([]uuid.UUID, error) {
	return r.q.ListOrganizationsDueForDeletion(ctx, maxRows)
}

// IsEmailVerified reports whether the user has a verified email — the gate for
// self-serve org creation.
func (r *Repository) IsEmailVerified(ctx context.Context, userID uuid.UUID) (bool, error) {
	return r.q.IsEmailVerified(ctx, userID)
}
