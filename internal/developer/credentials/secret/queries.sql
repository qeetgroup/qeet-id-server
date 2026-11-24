-- Per-organization secrets vault (table organization.secrets).
-- Values are stored encrypted at rest (AES-256-GCM); plaintext is only ever
-- returned via RevealSecret / GetSecretByName, and the service audits each read.

-- name: ListSecrets :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest. GetSecret
-- returns the same columns, so its row converts to this one.
SELECT s.id, s.name, s.scope, s.last4, s.created_at, s.updated_at,
       s.last_revealed_at, s.last_revealed_by, s.last_revealed_credential,
       u.email AS revealed_by_email, u.display_name AS revealed_by_name,
       s.value_changed_at, s.rotation_interval_days
FROM organization.secrets s
LEFT JOIN account.users u ON u.id = s.last_revealed_by
WHERE s.organization_id = @organization_id
ORDER BY s.created_at DESC
LIMIT 1001;

-- name: GetSecret :one
SELECT s.id, s.name, s.scope, s.last4, s.created_at, s.updated_at,
       s.last_revealed_at, s.last_revealed_by, s.last_revealed_credential,
       u.email AS revealed_by_email, u.display_name AS revealed_by_name,
       s.value_changed_at, s.rotation_interval_days
FROM organization.secrets s
LEFT JOIN account.users u ON u.id = s.last_revealed_by
WHERE s.id = @id AND s.organization_id = @organization_id;

-- name: CreateSecret :one
INSERT INTO organization.secrets (organization_id, name, scope, ciphertext, nonce, last4, rotation_interval_days)
VALUES (@organization_id, @name, @scope, @ciphertext, @nonce, @last4, sqlc.narg('rotation_interval_days'))
RETURNING id;

-- UpdateSecretValue gives one of the organization's secrets a new value, and
-- the scope and rotation interval when given (set_rotation; a NULL interval
-- removes it).
-- name: UpdateSecretValue :execrows
UPDATE organization.secrets
SET ciphertext = @ciphertext, nonce = @nonce, last4 = @last4, scope = COALESCE(sqlc.narg('scope'), scope),
    rotation_interval_days = CASE WHEN @set_rotation::bool THEN sqlc.narg('rotation_interval_days')::int ELSE rotation_interval_days END,
    value_changed_at = NOW(), updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- UpdateSecretSettings sets the scope and rotation interval of one of the
-- organization's secrets, each when given, keeping its value.
-- name: UpdateSecretSettings :execrows
UPDATE organization.secrets
SET scope = COALESCE(sqlc.narg('scope'), scope),
    rotation_interval_days = CASE WHEN @set_rotation::bool THEN sqlc.narg('rotation_interval_days')::int ELSE rotation_interval_days END,
    updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- name: MarkSecretRevealed :exec
-- Records who revealed the secret: a person, or a machine credential by its id.
UPDATE organization.secrets
SET last_revealed_at = NOW(), last_revealed_by = sqlc.narg('user_id'),
    last_revealed_credential = sqlc.narg('credential')
WHERE id = @id AND organization_id = @organization_id;

-- name: RevealSecret :one
SELECT name, ciphertext, nonce FROM organization.secrets WHERE id = $1 AND organization_id = $2;

-- name: GetSecretByName :one
SELECT id, ciphertext, nonce FROM organization.secrets WHERE organization_id = $1 AND name = $2;

-- name: DeleteSecret :execrows
DELETE FROM organization.secrets WHERE id = $1 AND organization_id = $2;
