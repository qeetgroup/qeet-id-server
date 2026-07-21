-- Per-tenant secrets vault (table tenant.secrets, migration 0039_secrets).
-- Values are stored encrypted at rest (AES-256-GCM); plaintext is only ever
-- returned via RevealSecret / GetSecretByName and always audited by the caller.

-- name: ListSecrets :many
SELECT id, name, scope, last4, created_at, updated_at
FROM tenant.secrets
WHERE tenant_id = $1
ORDER BY created_at DESC;

-- name: CreateSecret :one
INSERT INTO tenant.secrets (tenant_id, name, scope, ciphertext, nonce, last4)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, name, scope, last4, created_at, updated_at;

-- name: RevealSecret :one
SELECT name, ciphertext, nonce FROM tenant.secrets WHERE id = $1 AND tenant_id = $2;

-- name: GetSecretByName :one
SELECT id, ciphertext, nonce FROM tenant.secrets WHERE tenant_id = $1 AND name = $2;

-- name: DeleteSecret :execrows
DELETE FROM tenant.secrets WHERE id = $1 AND tenant_id = $2;
