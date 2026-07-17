-- Queries for the access/recovery domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: GetUserIDByEmailForTenant :one
SELECT id FROM "user".users
WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL;

-- name: InsertPasswordReset :exec
INSERT INTO auth.password_resets (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordResetByToken :one
SELECT id, user_id, expires_at, used_at
FROM auth.password_resets
WHERE token_hash = $1
FOR UPDATE;

-- name: UpsertPasswordCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();

-- name: MarkPasswordResetUsed :exec
UPDATE auth.password_resets SET used_at = NOW() WHERE id = $1;

-- name: RevokeUserSessions :exec
UPDATE auth.sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: InsertMagicLink :exec
INSERT INTO auth.magic_links (tenant_id, email, token_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetMagicLinkByToken :one
SELECT id, tenant_id, email, expires_at, used_at
FROM auth.magic_links
WHERE token_hash = $1
FOR UPDATE;

-- name: MarkMagicLinkUsed :exec
UPDATE auth.magic_links SET used_at = NOW() WHERE id = $1;
