package user

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/identity/users/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/dbutil"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// parseUserMetadata decodes the JSONB metadata column. JSONB is guaranteed
// valid JSON by Postgres, so a decode failure means data corruption or a
// codec mismatch; we log it and fall back to an empty map so the user
// remains usable for everything other than metadata.
func parseUserMetadata(raw []byte, userID uuid.UUID) map[string]any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Warn("user metadata unmarshal failed",
			"user_id", userID,
			"err", err,
			"meta_bytes", len(raw),
		)
		return map[string]any{}
	}
	if m == nil {
		return map[string]any{}
	}
	return m
}

type Repository struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, q: dbgen.New(pool)}
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

// pgtypeToUUIDPtr converts a pgtype.UUID returned by generated code to *uuid.UUID.
func pgtypeToUUIDPtr(p pgtype.UUID) *uuid.UUID {
	if !p.Valid {
		return nil
	}
	uid := uuid.UUID(p.Bytes)
	return &uid
}

// pgtypeToTimePtr converts a pgtype.Timestamptz returned by generated code to *time.Time.
func pgtypeToTimePtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// uuidToPgtype converts a uuid.UUID to the pgtype.UUID used by generated code.
func uuidToPgtype(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(id), Valid: true}
}

// uuidPtrToPgtype converts a *uuid.UUID to pgtype.UUID.
func uuidPtrToPgtype(p *uuid.UUID) pgtype.UUID {
	if p == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: [16]byte(*p), Valid: true}
}

func userFromInsertRow(row dbgen.InsertUserRow) *User {
	u := &User{
		ID:              row.ID,
		Email:           row.Email,
		Phone:           row.Phone,
		EmailVerifiedAt: pgtypeToTimePtr(row.EmailVerifiedAt),
		PhoneVerifiedAt: pgtypeToTimePtr(row.PhoneVerifiedAt),
		DisplayName:     row.DisplayName,
		Status:          row.Status,
		Metadata:        parseUserMetadata(row.Metadata, row.ID),
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
	if tid := pgtypeToUUIDPtr(row.TenantID); tid != nil {
		u.TenantID = *tid
	}
	return u
}

func userFromGetRow(row dbgen.GetUserByIDRow) *User {
	u := &User{
		ID:              row.ID,
		Email:           row.Email,
		Phone:           row.Phone,
		EmailVerifiedAt: pgtypeToTimePtr(row.EmailVerifiedAt),
		PhoneVerifiedAt: pgtypeToTimePtr(row.PhoneVerifiedAt),
		DisplayName:     row.DisplayName,
		AvatarURL:       row.AvatarUrl,
		Status:          row.Status,
		Metadata:        parseUserMetadata(row.Metadata, row.ID),
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
	}
	if tid := pgtypeToUUIDPtr(row.TenantID); tid != nil {
		u.TenantID = *tid
	}
	return u
}

// userFromEmailRow maps a GetUserByEmailRow, or the identically-shaped
// GetUserByEmailGlobalRow, to the domain User (avatar_url intentionally excluded).
func userFromEmailRow(
	id uuid.UUID,
	tenantID pgtype.UUID,
	email string,
	emailVerifiedAt pgtype.Timestamptz,
	phone *string,
	phoneVerifiedAt pgtype.Timestamptz,
	displayName *string,
	status string,
	metadata []byte,
	createdAt, updatedAt time.Time,
) *User {
	u := &User{
		ID:              id,
		Email:           email,
		Phone:           phone,
		EmailVerifiedAt: pgtypeToTimePtr(emailVerifiedAt),
		PhoneVerifiedAt: pgtypeToTimePtr(phoneVerifiedAt),
		DisplayName:     displayName,
		Status:          status,
		Metadata:        parseUserMetadata(metadata, id),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}
	if tid := pgtypeToUUIDPtr(tenantID); tid != nil {
		u.TenantID = *tid
	}
	return u
}

// userCols is the column list used by the hand-written Update RETURNING clause.
// The ordering matches exactly what Update scans via scanUser.
const userCols = `id, tenant_id, email, email_verified_at, phone, phone_verified_at,
                  display_name, status, metadata, created_at, updated_at`

// scanUser scans an 11-column user row (userCols, no avatar_url) into a User.
// Used only by the hand-written Update path.
func scanUser(row pgx.Row) (*User, error) {
	var u User
	var meta []byte
	var tid *uuid.UUID
	if err := row.Scan(&u.ID, &tid, &u.Email, &u.EmailVerifiedAt,
		&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
		&u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	if tid != nil {
		u.TenantID = *tid
	}
	u.Metadata = parseUserMetadata(meta, u.ID)
	return &u, nil
}

// CreateWithCredential inserts the user and (optionally, when passwordHash is
// non-empty) their password credential inside one tx.
func (r *Repository) CreateWithCredential(ctx context.Context, in CreateInput, passwordHash string) (*User, error) {
	meta := in.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var phone *string
	if in.Phone != "" {
		p := in.Phone
		phone = &p
	}
	var displayName *string
	if in.DisplayName != "" {
		d := in.DisplayName
		displayName = &d
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// InsertUser and the cross-context password credential are both static SQL, so
	// they run as sqlc queries on the same pgx.Tx via WithTx — one transaction across
	// the user and auth bounded contexts.
	q := r.q.WithTx(tx)
	row, err := q.InsertUser(ctx, dbgen.InsertUserParams{
		TenantID:    uuidToPgtype(in.TenantID),
		Email:       strings.TrimSpace(in.Email),
		Phone:       phone,
		DisplayName: displayName,
		Metadata:    metaJSON,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, errs.ErrConflict.
				WithMessage("An account with this email already exists in this workspace.").
				WithDetail("email already exists for tenant")
		}
		if pgxerr.IsForeignKey(err) {
			return nil, errs.ErrBadRequest.WithDetail("tenant does not exist")
		}
		return nil, err
	}
	u := userFromInsertRow(row)
	if passwordHash != "" {
		if err := q.InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
			UserID:       u.ID,
			PasswordHash: passwordHash,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// Get fetches a single user. Unlike the list/lookup paths it also selects
// avatar_url (the profile + header read it via this path); keeping it out of
// the shared userCols means the paginated users list never carries avatars.
func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	row, err := r.q.GetUserByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return userFromGetRow(row), nil
}

// TenantOf returns the tenant a user belongs to, regardless of soft-delete
// state (so it also guards restore/purge). Returns ErrNotFound for a missing
// user or a tenant-less one. Used to enforce that admin by-id operations never
// cross tenants (QID-18) — callers compare it to the requester's own tenant.
func (r *Repository) TenantOf(ctx context.Context, id uuid.UUID) (uuid.UUID, error) {
	raw, err := r.q.GetUserTenantOf(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if !raw.Valid {
		return uuid.Nil, errs.ErrNotFound
	}
	return uuid.UUID(raw.Bytes), nil
}

func (r *Repository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*User, error) {
	row, err := r.q.GetUserByEmail(ctx, dbgen.GetUserByEmailParams{
		TenantID: uuidToPgtype(tenantID),
		Lower:    email,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return userFromEmailRow(row.ID, row.TenantID, row.Email, row.EmailVerifiedAt, row.Phone,
		row.PhoneVerifiedAt, row.DisplayName, row.Status, row.Metadata, row.CreatedAt, row.UpdatedAt), nil
}

// GetByEmailGlobal looks up a user by email across all tenants.
// Email is enforced globally unique by migration 0022, so this returns
// at most one row. Used by the tenant-less sign-in flow.
func (r *Repository) GetByEmailGlobal(ctx context.Context, email string) (*User, error) {
	row, err := r.q.GetUserByEmailGlobal(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return userFromEmailRow(row.ID, row.TenantID, row.Email, row.EmailVerifiedAt, row.Phone,
		row.PhoneVerifiedAt, row.DisplayName, row.Status, row.Metadata, row.CreatedAt, row.UpdatedAt), nil
}

// ListByTenant returns a tenant's members, defined by rbac.user_roles membership (not users.tenant_id).
// The roles subquery returns text[] which sqlc infers as interface{}; these two variants
// remain hand-written so we can scan into the correct []string target type.
func (r *Repository) ListByTenant(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) ([]User, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var (
		rows pgx.Rows
		err  error
	)
	if cursor == "" {
		rows, err = r.pool.Query(ctx, `
			SELECT `+userCols+`,
			  COALESCE((
				SELECT array_agg(r.name ORDER BY r.name)
				FROM rbac.user_roles ur2
				JOIN rbac.roles r ON r.id = ur2.role_id
				WHERE ur2.user_id = "user".users.id AND ur2.tenant_id = $1
			  ), '{}') AS roles
			FROM "user".users
			WHERE deleted_at IS NULL
			  AND EXISTS (
				SELECT 1 FROM rbac.user_roles ur
				WHERE ur.user_id = "user".users.id AND ur.tenant_id = $1
			  )
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, tenantID, limit+1)
	} else {
		// Cursor: opaque base64(createdAt|id); tuple inequality hits the composite index.
		curT, curID, perr := paging.DecodeTimeUUID(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err = r.pool.Query(ctx, `
			SELECT `+userCols+`,
			  COALESCE((
				SELECT array_agg(r.name ORDER BY r.name)
				FROM rbac.user_roles ur2
				JOIN rbac.roles r ON r.id = ur2.role_id
				WHERE ur2.user_id = "user".users.id AND ur2.tenant_id = $1
			  ), '{}') AS roles
			FROM "user".users
			WHERE deleted_at IS NULL
			  AND EXISTS (
				SELECT 1 FROM rbac.user_roles ur
				WHERE ur.user_id = "user".users.id AND ur.tenant_id = $1
			  )
			  AND (created_at, id) < ($2, $3)
			ORDER BY created_at DESC, id DESC
			LIMIT $4
		`, tenantID, curT, curID, limit+1)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var meta []byte
		var tid *uuid.UUID
		var roles []string
		if err := rows.Scan(&u.ID, &tid, &u.Email, &u.EmailVerifiedAt,
			&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
			&u.CreatedAt, &u.UpdatedAt, &roles); err != nil {
			return nil, "", err
		}
		if tid != nil {
			u.TenantID = *tid
		}
		u.Roles = roles
		u.Metadata = parseUserMetadata(meta, u.ID)
		out = append(out, u)
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
func (r *Repository) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*User, error) {
	ub := dbutil.NewUpdate()
	if in.DisplayName != nil {
		ub.Set("display_name", *in.DisplayName)
	}
	if in.AvatarURL != nil {
		ub.Set("avatar_url", *in.AvatarURL)
	}
	if in.Phone != nil {
		ub.Set("phone", *in.Phone)
	}
	if in.Status != nil {
		ub.Set("status", *in.Status)
	}
	if in.Metadata != nil {
		meta, err := json.Marshal(in.Metadata)
		if err != nil {
			return nil, err
		}
		ub.Set("metadata", meta)
	}
	if ub.Empty() {
		return r.Get(ctx, id)
	}
	ub.SetRaw("updated_at = NOW()")
	idAt := ub.NextPlaceholder()
	args := append(ub.Args(), id)
	q := `UPDATE "user".users SET ` + ub.Assignments() +
		` WHERE id = $` + strconv.Itoa(idAt) + ` AND deleted_at IS NULL RETURNING ` + userCols
	row := r.pool.QueryRow(ctx, q, args...)
	return scanUser(row)
}

func (r *Repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.SoftDeleteUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// ListDeleted returns a tenant's soft-deleted users (most recent first).
func (r *Repository) ListDeleted(ctx context.Context, tenantID uuid.UUID, limit int) ([]DeletedUser, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := r.q.ListDeletedUsers(ctx, dbgen.ListDeletedUsersParams{
		TenantID: uuidToPgtype(tenantID),
		Limit:    int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := []DeletedUser{}
	for _, row := range rows {
		d := DeletedUser{
			ID:          row.ID,
			Email:       row.Email,
			DisplayName: row.DisplayName,
			CreatedAt:   row.CreatedAt,
		}
		// The query filters WHERE deleted_at IS NOT NULL, so the value is always valid.
		if row.DeletedAt.Valid {
			d.DeletedAt = row.DeletedAt.Time
		}
		out = append(out, d)
	}
	return out, nil
}

// Restore reverses a soft delete. Returns ErrNotFound if the user isn't
// currently soft-deleted.
func (r *Repository) Restore(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.RestoreUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Purge permanently removes a soft-deleted user (and, via ON DELETE CASCADE,
// its sessions/credentials/identities). Only acts on already-soft-deleted rows.
func (r *Repository) Purge(ctx context.Context, id uuid.UUID) error {
	n, err := r.q.PurgeUser(ctx, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *Repository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.q.MarkEmailVerified(ctx, id)
}

// PasswordHash returns the bcrypt hash for the user, or "" if no password
// credential exists.
func (r *Repository) PasswordHash(ctx context.Context, id uuid.UUID) (string, error) {
	h, err := r.q.GetPasswordHash(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return h, err
}

func (r *Repository) SetPassword(ctx context.Context, id uuid.UUID, hash string) error {
	return r.q.SetPassword(ctx, dbgen.SetPasswordParams{UserID: id, PasswordHash: hash})
}
