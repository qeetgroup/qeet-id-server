-- Queries for the api-keys domain.
-- All queries are static; no dynamic SQL in this domain.

-- name: CreateAPIKey :one
INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash, scopes, expires_at, created_by, rotated_from)
VALUES (@tenant_id, @user_id, @name, @prefix, @key_hash, @scopes, @expires_at, sqlc.narg('created_by'), sqlc.narg('rotated_from'))
RETURNING id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at, created_by, rotated_from;

-- name: ListAPIKeys :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at, created_by, rotated_from
FROM auth.api_keys
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT 1001;

-- CountActiveAPIKeys counts a tenant's non-revoked keys — the plan-limit check.
-- name: CountActiveAPIKeys :one
SELECT COUNT(*) FROM auth.api_keys
WHERE tenant_id = $1 AND revoked_at IS NULL;

-- name: RevokeAPIKey :execrows
UPDATE auth.api_keys SET revoked_at = NOW() WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL;

-- VerifyAPIKey fetches by prefix for the auth path; includes key_hash for
-- bcrypt/argon2 comparison. Only non-revoked keys are eligible.
-- VerifyAPIKey finds a live key by its prefix. A personal key works only
-- while its person's account is active, so suspending, deleting or
-- deprovisioning them stops it too, and any key only while its organisation
-- is active.
-- name: VerifyAPIKey :one
SELECT k.id, k.tenant_id, k.user_id, k.name, k.prefix, k.scopes, k.expires_at, k.last_used_at, k.revoked_at, k.created_at, k.key_hash
FROM auth.api_keys k
JOIN tenant.tenants t ON t.id = k.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL
LEFT JOIN account.users u ON u.id = k.user_id
WHERE k.prefix = $1 AND k.revoked_at IS NULL
  AND (k.user_id IS NULL OR (u.status = 'active' AND u.deleted_at IS NULL));

-- name: APIKeyLive :one
-- Whether a key would still authenticate, as VerifyAPIKey decides: not revoked
-- or expired, its organisation and the person it acts for, if any, still
-- active.
SELECT EXISTS (
    SELECT 1 FROM auth.api_keys k
    JOIN tenant.tenants t ON t.id = k.tenant_id AND t.status = 'active' AND t.deleted_at IS NULL
    LEFT JOIN account.users u ON u.id = k.user_id
    WHERE k.id = @id AND k.tenant_id = @tenant_id AND k.revoked_at IS NULL
      AND (k.expires_at IS NULL OR k.expires_at > NOW())
      AND (k.user_id IS NULL OR (u.status = 'active' AND u.deleted_at IS NULL))
)::bool;

-- name: TouchAPIKeyLastUsed :exec
UPDATE auth.api_keys SET last_used_at = NOW() WHERE id = $1;

-- UpgradeAPIKeyHash replaces an Argon2id key hash from before with its SHA-256
-- form, once the key has verified. A concurrent rotation keeps its own hash.
-- name: UpgradeAPIKeyHash :exec
UPDATE auth.api_keys SET key_hash = @new_hash
WHERE id = @id AND tenant_id = @tenant_id AND key_hash = @old_hash;

-- name: LockAPIKeyForRotation :one
-- A live key of the tenant, held while it is replaced.
SELECT id, user_id, name, scopes, expires_at FROM auth.api_keys
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
FOR UPDATE;

-- name: EndAPIKeyAt :exec
-- The replaced key stops at until, or at once.
UPDATE auth.api_keys
SET expires_at = LEAST(COALESCE(expires_at, @until::timestamptz), @until::timestamptz),
    revoked_at = CASE WHEN @until::timestamptz <= NOW() THEN NOW() ELSE revoked_at END
WHERE id = @id AND tenant_id = @tenant_id;

-- APIKeyScopes returns the scopes of one of the tenant's API keys.
-- name: APIKeyScopes :one
SELECT scopes FROM auth.api_keys WHERE id = @id AND tenant_id = @tenant_id;
