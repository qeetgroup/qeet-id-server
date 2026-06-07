package user

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/internal/platform/dbutil"
	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/paging"
	"github.com/qeetgroup/qeet-id/internal/platform/pgxerr"
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
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func (r *Repository) Pool() *pgxpool.Pool { return r.pool }

const userCols = `id, tenant_id, email, email_verified_at, phone, phone_verified_at,
                  display_name, status, metadata, created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	var meta []byte
	// tenant_id is nullable (tenant-less user); scan via pointer.
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

// CreateWithCredential inserts the user and (optionally) their password
// credential inside one tx. Returns the new user along with a flag the
// caller can use to know whether a password was set.
func (r *Repository) CreateWithCredential(ctx context.Context, in CreateInput, passwordHash string) (*User, error) {
	meta := in.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	var displayName any
	if in.DisplayName != "" {
		displayName = in.DisplayName
	}
	var phone any
	if in.Phone != "" {
		phone = in.Phone
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, phone, display_name, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+userCols,
		in.TenantID, strings.TrimSpace(in.Email), phone, displayName, metaJSON,
	)
	u, err := scanUser(row)
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
	if passwordHash != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO auth.password_credentials (user_id, password_hash)
			VALUES ($1, $2)
		`, u.ID, passwordHash); err != nil {
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
	var u User
	var meta []byte
	var tid *uuid.UUID
	err := r.pool.QueryRow(ctx,
		`SELECT `+userCols+`, avatar_url FROM "user".users WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&u.ID, &tid, &u.Email, &u.EmailVerifiedAt, &u.Phone, &u.PhoneVerifiedAt,
			&u.DisplayName, &u.Status, &meta, &u.CreatedAt, &u.UpdatedAt, &u.AvatarURL)
	if err != nil {
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

func (r *Repository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+userCols+`
		FROM "user".users
		WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL
	`, tenantID, email)
	return scanUser(row)
}

// GetByEmailGlobal looks up a user by email across all tenants.
// Email is enforced globally unique by migration 0022, so this returns
// at most one row. Used by the tenant-less sign-in flow.
func (r *Repository) GetByEmailGlobal(ctx context.Context, email string) (*User, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT `+userCols+`
		FROM "user".users
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, email)
	return scanUser(row)
}

// ListByTenant returns a tenant's members, defined by rbac.user_roles membership (not users.tenant_id).
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
	ct, err := r.pool.Exec(ctx, `
		UPDATE "user".users
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

// ListDeleted returns a tenant's soft-deleted users (most recent first).
func (r *Repository) ListDeleted(ctx context.Context, tenantID uuid.UUID, limit int) ([]DeletedUser, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, email, display_name, deleted_at, created_at
		FROM "user".users
		WHERE tenant_id = $1 AND deleted_at IS NOT NULL
		ORDER BY deleted_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeletedUser{}
	for rows.Next() {
		var d DeletedUser
		if err := rows.Scan(&d.ID, &d.Email, &d.DisplayName, &d.DeletedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Restore reverses a soft delete. Returns ErrNotFound if the user isn't
// currently soft-deleted.
func (r *Repository) Restore(ctx context.Context, id uuid.UUID) error {
	ct, err := r.pool.Exec(ctx, `
		UPDATE "user".users
		SET deleted_at = NULL, status = 'active', updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NOT NULL
	`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Purge permanently removes a soft-deleted user (and, via ON DELETE CASCADE,
// its sessions/credentials/identities). Only acts on already-soft-deleted rows.
func (r *Repository) Purge(ctx context.Context, id uuid.UUID) error {
	ct, err := r.pool.Exec(ctx, `DELETE FROM "user".users WHERE id = $1 AND deleted_at IS NOT NULL`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

func (r *Repository) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE "user".users
		SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL
	`, id)
	return err
}

// PasswordHash returns the bcrypt hash for the user, or "" if no password
// credential exists.
func (r *Repository) PasswordHash(ctx context.Context, id uuid.UUID) (string, error) {
	var h string
	err := r.pool.QueryRow(ctx, `
		SELECT password_hash FROM auth.password_credentials WHERE user_id = $1
	`, id).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return h, err
}

func (r *Repository) SetPassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, id, hash)
	return err
}
