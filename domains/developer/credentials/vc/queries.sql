-- Queries for the Verifiable Credentials domain.
-- All queries are static; signing/verification logic stays in the Service layer.

-- name: CreateCredential :one
INSERT INTO auth.credentials (tenant_id, subject, type, claims, expires_at)
VALUES (@tenant_id, @subject, @type, @claims, @expires_at)
RETURNING id, issued_at;

-- GetCredentialRevocation checks the revocation registry for a presented
-- JWT-VC (jti = credential id). Absent record is treated as valid by the caller.
-- name: GetCredentialRevocation :one
SELECT revoked_at FROM auth.credentials WHERE id = $1;

-- name: ListCredentials :many
SELECT id, subject, type, issued_at, expires_at, revoked_at
FROM auth.credentials WHERE tenant_id = $1 ORDER BY issued_at DESC LIMIT 200;

-- name: RevokeCredential :execrows
UPDATE auth.credentials SET revoked_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL;
