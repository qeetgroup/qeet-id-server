-- Per-tenant secrets vault (table tenant.secrets, migration 0039_secrets).
-- Values are stored encrypted at rest (AES-256-GCM); plaintext is only ever
-- returned via RevealSecret / GetSecretByName and always audited by the caller.

-- name: ListSecrets :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest. GetSecret
-- returns the same columns, so its row converts to this one.
SELECT s.id, s.name, s.scope, s.last4, s.created_at, s.updated_at,
       s.last_revealed_at, s.last_revealed_by, s.last_revealed_credential,
       u.email AS revealed_by_email, u.display_name AS revealed_by_name,
       s.value_changed_at, s.rotation_interval_days
FROM tenant.secrets s
LEFT JOIN account.users u ON u.id = s.last_revealed_by
WHERE s.tenant_id = @tenant_id
ORDER BY s.created_at DESC
LIMIT 1001;

-- name: GetSecret :one
SELECT s.id, s.name, s.scope, s.last4, s.created_at, s.updated_at,
       s.last_revealed_at, s.last_revealed_by, s.last_revealed_credential,
       u.email AS revealed_by_email, u.display_name AS revealed_by_name,
       s.value_changed_at, s.rotation_interval_days
FROM tenant.secrets s
LEFT JOIN account.users u ON u.id = s.last_revealed_by
WHERE s.id = @id AND s.tenant_id = @tenant_id;

-- name: CreateSecret :one
INSERT INTO tenant.secrets (tenant_id, name, scope, ciphertext, nonce, last4, rotation_interval_days)
VALUES (@tenant_id, @name, @scope, @ciphertext, @nonce, @last4, sqlc.narg('rotation_interval_days'))
RETURNING id;

-- name: MarkSecretRevealed :exec
-- Records who revealed the secret: a person, or a machine credential by its id.
UPDATE tenant.secrets
SET last_revealed_at = NOW(), last_revealed_by = sqlc.narg('user_id'),
    last_revealed_credential = sqlc.narg('credential')
WHERE id = @id AND tenant_id = @tenant_id;

-- name: RevealSecret :one
SELECT name, ciphertext, nonce FROM tenant.secrets WHERE id = $1 AND tenant_id = $2;

-- name: GetSecretByName :one
SELECT id, ciphertext, nonce FROM tenant.secrets WHERE tenant_id = $1 AND name = $2;

-- name: DeleteSecret :execrows
DELETE FROM tenant.secrets WHERE id = $1 AND tenant_id = $2;
