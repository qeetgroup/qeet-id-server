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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
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
	if err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.EmailVerifiedAt,
		&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
		&u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, errs.ErrConflict.WithDetail("email already exists for tenant")
		}
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
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

func (r *Repository) Get(ctx context.Context, id uuid.UUID) (*User, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+userCols+` FROM "user".users WHERE id = $1 AND deleted_at IS NULL`, id)
	return scanUser(row)
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
			SELECT `+userCols+`
			FROM "user".users
			WHERE tenant_id = $1 AND deleted_at IS NULL
			ORDER BY created_at DESC, id DESC
			LIMIT $2
		`, tenantID, limit+1)
	} else {
		cur, perr := uuid.Parse(cursor)
		if perr != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		rows, err = r.pool.Query(ctx, `
			SELECT `+userCols+`
			FROM "user".users
			WHERE tenant_id = $1 AND deleted_at IS NULL
			  AND (created_at, id) <
			      (SELECT created_at, id FROM "user".users WHERE id = $2)
			ORDER BY created_at DESC, id DESC
			LIMIT $3
		`, tenantID, cur, limit+1)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		var meta []byte
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.EmailVerifiedAt,
			&u.Phone, &u.PhoneVerifiedAt, &u.DisplayName, &u.Status, &meta,
			&u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, "", err
		}
		u.Metadata = parseUserMetadata(meta, u.ID)
		out = append(out, u)
	}
	var next string
	if len(out) > limit {
		next = out[limit].ID.String()
		out = out[:limit]
	}
	return out, next, nil
}

func (r *Repository) Update(ctx context.Context, id uuid.UUID, in UpdateInput) (*User, error) {
	var (
		sets []string
		args []any
		i    = 1
	)
	if in.DisplayName != nil {
		sets = append(sets, "display_name = $"+strconv.Itoa(i))
		args = append(args, *in.DisplayName)
		i++
	}
	if in.Phone != nil {
		sets = append(sets, "phone = $"+strconv.Itoa(i))
		args = append(args, *in.Phone)
		i++
	}
	if in.Status != nil {
		sets = append(sets, "status = $"+strconv.Itoa(i))
		args = append(args, *in.Status)
		i++
	}
	if in.Metadata != nil {
		meta, _ := json.Marshal(in.Metadata)
		sets = append(sets, "metadata = $"+strconv.Itoa(i))
		args = append(args, meta)
		i++
	}
	if len(sets) == 0 {
		return r.Get(ctx, id)
	}
	sets = append(sets, "updated_at = NOW()")
	args = append(args, id)
	q := `UPDATE "user".users SET ` + strings.Join(sets, ", ") +
		` WHERE id = $` + strconv.Itoa(i) + ` AND deleted_at IS NULL RETURNING ` + userCols
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
