-- Queries for the api-keys domain.
-- All queries are static; no dynamic SQL in this domain.

-- name: CreateAPIKey :one
INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash, scopes, expires_at)
VALUES (@tenant_id, @user_id, @name, @prefix, @key_hash, @scopes, @expires_at)
RETURNING id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at;

-- name: ListAPIKeys :many
SELECT id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at
FROM auth.api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- CountActiveAPIKeys counts a tenant's non-revoked keys — the plan-limit check.
-- name: CountActiveAPIKeys :one
SELECT COUNT(*) FROM auth.api_keys
WHERE tenant_id = $1 AND revoked_at IS NULL;

-- name: RevokeAPIKey :execrows
UPDATE auth.api_keys SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL;

-- VerifyAPIKey fetches by prefix for the auth path; includes key_hash for
-- bcrypt/argon2 comparison. Only non-revoked keys are eligible.
-- name: VerifyAPIKey :one
SELECT id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at, key_hash
FROM auth.api_keys
WHERE prefix = $1 AND revoked_at IS NULL;

-- name: TouchAPIKeyLastUsed :exec
UPDATE auth.api_keys SET last_used_at = NOW() WHERE id = $1;

-- UpgradeAPIKeyHash replaces an Argon2id key hash from before with its SHA-256
-- form, once the key has verified. A concurrent rotation keeps its own hash.
-- name: UpgradeAPIKeyHash :exec
UPDATE auth.api_keys SET key_hash = @new_hash
WHERE id = @id AND tenant_id = @tenant_id AND key_hash = @old_hash;
