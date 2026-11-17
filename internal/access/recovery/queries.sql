-- Queries for the access/recovery domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: GetUserIDByEmailForTenant :one
SELECT id FROM account.users
WHERE tenant_id = $1 AND LOWER(email) = LOWER($2) AND deleted_at IS NULL;

-- ExpirePasswordResets ends the user's unused reset links, so only the newest
-- works. Set a minute back, so a clock behind the database's sees them ended.
-- name: ExpirePasswordResets :exec
UPDATE auth.password_resets SET expires_at = NOW() - INTERVAL '1 minute'
WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW() - INTERVAL '1 minute';

-- name: InsertPasswordReset :exec
INSERT INTO auth.password_resets (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordResetByToken :one
SELECT id, user_id, expires_at, used_at
FROM auth.password_resets
WHERE token_hash = $1
FOR UPDATE;

-- GetResetAccount returns the organisation (NULL = none) and email of the
-- account a reset is for, so the new password is checked against its rules.
-- name: GetResetAccount :one
SELECT tenant_id, email FROM account.users WHERE id = $1;

-- name: UpsertPasswordCredential :exec
INSERT INTO auth.password_credentials (user_id, password_hash, updated_at)
VALUES ($1, $2, NOW())
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();

-- name: MarkPasswordResetUsed :exec
UPDATE auth.password_resets SET used_at = NOW() WHERE id = $1;

-- name: VerifyEmailByLink :one
-- A used reset or sign-in link was sent to the account's address and to nobody
-- else, so it proves the person owns the address: verify it if it wasn't. No
-- row when it already was.
UPDATE account.users SET email_verified_at = NOW(), updated_at = NOW()
WHERE id = @user_id AND email_verified_at IS NULL AND deleted_at IS NULL
RETURNING email;

-- name: RevokeUserSessions :exec
UPDATE auth.sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL;

-- ExpireMagicLinks ends the unused sign-in links to an address, so only the
-- newest works; a minute back, as ExpirePasswordResets.
-- name: ExpireMagicLinks :exec
UPDATE auth.magic_links SET expires_at = NOW() - INTERVAL '1 minute'
WHERE LOWER(email) = LOWER(@email) AND used_at IS NULL AND expires_at > NOW() - INTERVAL '1 minute';

-- InsertMagicLink stores a link (only its token's hash). tenant_id is the
-- organisation it was asked for from (NULL from the console); app is where it
-- opens and return_to where the hosted journey continues.
-- name: InsertMagicLink :exec
INSERT INTO auth.magic_links (tenant_id, email, token_hash, expires_at, app, return_to)
VALUES (sqlc.narg('tenant_id'), @email, @token_hash, @expires_at, @app, sqlc.narg('return_to'));

-- name: GetMagicLinkByToken :one
SELECT id, tenant_id, email, expires_at, used_at, app, return_to
FROM auth.magic_links
WHERE token_hash = $1
FOR UPDATE;

-- GetMagicLinkAccount finds the account a magic link signs in to: by its
-- address, platform-wide (an address is unique), not deleted or suspended.
-- email is the address as stored, which links are sent to.
-- name: GetMagicLinkAccount :one
SELECT id, tenant_id, email FROM account.users
WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL AND status <> 'suspended';

-- name: MarkMagicLinkUsed :exec
UPDATE auth.magic_links SET used_at = NOW() WHERE id = $1;

-- AccountBelongsTo reports whether the account belongs to the organisation: it
-- is the account's home, or the account holds a role there.
-- name: AccountBelongsTo :one
SELECT EXISTS (
    SELECT 1 FROM account.users WHERE id = @user_id AND tenant_id = @tenant_id::uuid
    UNION ALL
    SELECT 1 FROM rbac.user_roles WHERE user_id = @user_id AND tenant_id = @tenant_id::uuid
)::bool AS belongs;
