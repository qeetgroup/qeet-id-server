-- Queries for the access/passkeys domain.
-- All queries are static and compiled by sqlc into ./dbgen.

-- name: ListPasskeyCredentials :many
SELECT id, user_id, name, transports, last_used_at, created_at
FROM auth.passkey_credentials WHERE user_id = $1 ORDER BY created_at DESC;

-- name: DeletePasskeyCredential :execrows
DELETE FROM auth.passkey_credentials WHERE id = $1 AND user_id = $2;

-- name: GetUserForWebAuthn :one
SELECT email, display_name, tenant_id FROM "user".users
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetUserIDByEmail :one
SELECT id FROM "user".users
WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL;

-- name: GetPasskeyCredentialsForCeremony :many
SELECT credential_id, public_key, sign_count, aaguid, transports
FROM auth.passkey_credentials WHERE user_id = $1;

-- name: InsertWebAuthnSession :one
INSERT INTO auth.webauthn_sessions (user_id, kind, data, expires_at)
VALUES ($1, $2, $3, $4) RETURNING id;

-- TakeWebAuthnSession atomically removes a session and returns its data (single-use).

-- name: TakeWebAuthnSession :one
DELETE FROM auth.webauthn_sessions WHERE id = $1
RETURNING kind, user_id, data, expires_at;

-- name: InsertSignupWebAuthnSession :one
INSERT INTO auth.webauthn_sessions (kind, data, expires_at, subject_id, pending_email, pending_display_name, pending_tenant_id)
VALUES ('signup', $1, $2, $3, $4, $5, $6) RETURNING id;

-- TakeSignupWebAuthnSession atomically removes a signup session and returns its data.

-- name: TakeSignupWebAuthnSession :one
DELETE FROM auth.webauthn_sessions WHERE id = $1
RETURNING kind, data, expires_at, subject_id, pending_email, pending_display_name, pending_tenant_id;

-- CheckEmailExistsNoTenant checks if an email is taken by a real user or a pending
-- signup session for the tenant-less flow.

-- name: CheckEmailExistsNoTenant :one
SELECT EXISTS (
    SELECT 1 FROM "user".users
    WHERE LOWER(email) = LOWER($1) AND tenant_id IS NULL AND deleted_at IS NULL
) OR EXISTS (
    SELECT 1 FROM auth.webauthn_sessions
    WHERE kind = 'signup' AND LOWER(pending_email) = LOWER($1)
      AND pending_tenant_id IS NULL AND expires_at > now()
) AS exists;

-- CheckEmailExistsForTenant checks if an email is taken for a specific tenant.

-- name: CheckEmailExistsForTenant :one
SELECT EXISTS (
    SELECT 1 FROM "user".users
    WHERE LOWER(email) = LOWER($1) AND tenant_id = $2 AND deleted_at IS NULL
) OR EXISTS (
    SELECT 1 FROM auth.webauthn_sessions
    WHERE kind = 'signup' AND LOWER(pending_email) = LOWER($1)
      AND pending_tenant_id = $2 AND expires_at > now()
) AS exists;

-- name: InsertUserFromSignup :one
INSERT INTO "user".users (tenant_id, email, display_name)
VALUES ($1, $2, $3)
RETURNING id;

-- name: InsertPasskeyCredential :exec
INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, aaguid, transports, name)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdatePasskeySignCount :exec
UPDATE auth.passkey_credentials SET sign_count = $1, last_used_at = NOW()
WHERE credential_id = $2;
