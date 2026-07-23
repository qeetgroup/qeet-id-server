-- Queries for the authentication domain.
-- Static queries with fully-typed, non-nullable parameters are converted.
-- Queries involving nullable UUID columns passed as Go interface{}/nil
-- (sessions.tenant_id, mfa_login_challenges.tenant_id, trusted_devices.tenant_id)
-- remain hand-written because they require Go-nil → SQL NULL semantics that
-- sqlc's uuid override cannot express without additional NULLIF wrappers that
-- would silently treat the zero UUID as NULL.
-- The Refresh join (FOR UPDATE OF rt across three tables) is also left raw.

-- name: GetLoginAttempt :one
-- Returns the locked_until column for a given email; pgx.ErrNoRows when no row.
SELECT locked_until FROM auth.login_attempts WHERE email = @email;

-- name: UpsertLoginAttempt :one
-- Upserts the failed-login counter. @window_start resets the counter when the
-- last failure is older than the failure window; @max_failed_logins and
-- @lock_until trigger the lockout.
INSERT INTO auth.login_attempts (email, failed_count, first_failed_at, last_failed_at)
VALUES (@email, 1, NOW(), NOW())
ON CONFLICT (email) DO UPDATE SET
    failed_count = CASE
        WHEN login_attempts.last_failed_at < @window_start THEN 1
        ELSE login_attempts.failed_count + 1 END,
    first_failed_at = CASE
        WHEN login_attempts.last_failed_at < @window_start THEN NOW()
        ELSE login_attempts.first_failed_at END,
    last_failed_at = NOW(),
    locked_until = CASE
        WHEN (CASE
            WHEN login_attempts.last_failed_at < @window_start THEN 1
            ELSE login_attempts.failed_count + 1 END) >= @max_failed_logins::int4
        THEN @lock_until::timestamptz ELSE NULL END
RETURNING failed_count;

-- name: DeleteLoginAttempt :exec
DELETE FROM auth.login_attempts WHERE email = @email;

-- name: InsertLoginSession :exec
INSERT INTO auth.login_sessions (token_hash, user_id, expires_at, ip, user_agent)
VALUES (@token_hash, @user_id, @expires_at, NULLIF(@ip::text, '')::inet, @user_agent);

-- name: GetLoginSession :one
SELECT user_id, expires_at FROM auth.login_sessions WHERE token_hash = @token_hash;

-- name: DeleteLoginSession :exec
DELETE FROM auth.login_sessions WHERE token_hash = @token_hash;

-- name: TouchTrustedDevice :execrows
-- Refreshes last_used_at and returns 1 when a live token was found, 0 otherwise.
UPDATE auth.trusted_devices SET last_used_at = NOW()
WHERE token_hash = @token_hash AND user_id = @user_id AND expires_at > NOW();

-- name: CheckTenantMembership :one
SELECT EXISTS (
    SELECT 1 FROM rbac.user_roles WHERE user_id = @user_id AND tenant_id = @tenant_id
) AS is_member;

-- name: UpdatePasswordCredentialHash :exec
UPDATE auth.password_credentials SET password_hash = @password_hash, updated_at = NOW()
WHERE user_id = @user_id;

-- name: InsertRefreshToken :one
INSERT INTO auth.refresh_tokens (session_id, token_hash, expires_at)
VALUES (@session_id, @token_hash, @expires_at)
RETURNING id;

-- name: MarkRefreshTokenUsed :exec
UPDATE auth.refresh_tokens SET used_at = NOW(), replaced_by = @replaced_by WHERE id = @id;

-- name: UpdateSessionLastSeen :exec
UPDATE auth.sessions SET last_seen_at = NOW() WHERE id = @session_id;

-- name: RevokeSessionById :exec
-- Idempotent: no-op on an already-revoked session.
UPDATE auth.sessions SET revoked_at = NOW()
WHERE id = @session_id AND revoked_at IS NULL;

-- name: InsertPasswordCredential :exec
-- Stores the Argon2id hash for a newly created identity (signup / hosted register).
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES (@user_id, @password_hash);

-- name: InsertTenantlessUser :one
-- Tenant-less signup: creates the identity with tenant_id NULL (a literal, not a
-- bind — membership lives in rbac.user_roles). display_name is nullable text.
INSERT INTO "user".users (tenant_id, email, display_name)
VALUES (NULL, @email, @display_name)
RETURNING id, created_at, updated_at;

-- name: InsertTenantlessSession :exec
-- Tenant-less session: tenant_id is a literal NULL (not a bind). ip goes through
-- NULLIF so an empty string stores as SQL NULL, matching InsertLoginSession.
INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent)
VALUES (@id, @user_id, NULL, NULLIF(@ip::text, '')::inet, @user_agent);

-- name: DeleteMFALoginChallenge :exec
DELETE FROM auth.mfa_login_challenges WHERE id = @id;
