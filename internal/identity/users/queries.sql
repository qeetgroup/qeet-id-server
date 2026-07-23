-- Queries for the users domain.
-- Static queries live here; the partial-UPDATE method (Update) stays hand-written
-- (dbutil.UpdateBuilder builds the SET clause dynamically).
-- CreateWithCredential inserts the user and (optionally) their password credential
-- in one tx; both halves are static and run as sqlc queries on the same pgx.Tx.

-- InsertUser is the user-row half of CreateWithCredential; the cross-context
-- password credential is inserted by InsertPasswordCredential on the same tx.
-- name: InsertUser :one
INSERT INTO "user".users (tenant_id, email, phone, display_name, metadata)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, tenant_id, email, email_verified_at, phone, phone_verified_at,
          display_name, status, metadata, created_at, updated_at;

-- InsertPasswordCredential is the password-credential half of CreateWithCredential.
-- It writes into the auth bounded context but is fixed SQL, so it runs on the shared tx.
-- name: InsertPasswordCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES ($1, $2);

-- GetUserByID fetches the full user row including avatar_url (read by the
-- profile / header paths that want to render the avatar).
-- name: GetUserByID :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at, avatar_url
FROM "user".users WHERE id = $1 AND deleted_at IS NULL;

-- GetUserTenantOf returns the tenant a user belongs to regardless of soft-delete
-- (used to enforce that admin by-id operations never cross tenant boundaries).
-- name: GetUserTenantOf :one
SELECT tenant_id FROM "user".users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at
FROM "user".users
WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL;

-- GetUserByEmailGlobal looks up a user by email across all tenants (email is
-- globally unique since migration 0022).
-- name: GetUserByEmailGlobal :one
SELECT id, tenant_id, email, email_verified_at, phone, phone_verified_at,
       display_name, status, metadata, created_at, updated_at
FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL;

-- ListUsersByTenant and ListUsersByTenantAfter are left hand-written in
-- repository.go because the COALESCE(array_agg(...), '{}'::text[]) expression
-- causes sqlc to infer Roles as interface{}, making the generated scan
-- unusable. Those two methods continue to use pool.Query with the original SQL.

-- name: SoftDeleteUser :execrows
UPDATE "user".users
SET deleted_at = NOW(), status = 'deleted', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListDeletedUsers :many
SELECT id, email, display_name, deleted_at, created_at
FROM "user".users
WHERE tenant_id = $1 AND deleted_at IS NOT NULL
ORDER BY deleted_at DESC
LIMIT $2;

-- name: RestoreUser :execrows
UPDATE "user".users
SET deleted_at = NULL, status = 'active', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NOT NULL;

-- name: PurgeUser :execrows
DELETE FROM "user".users WHERE id = $1 AND deleted_at IS NOT NULL;

-- name: MarkEmailVerified :exec
UPDATE "user".users
SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetPasswordHash :one
SELECT password_hash FROM auth.password_credentials WHERE user_id = $1;

-- name: SetPassword :exec
INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();
