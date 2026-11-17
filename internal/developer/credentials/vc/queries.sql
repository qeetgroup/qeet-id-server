-- Queries for the Verifiable Credentials domain.
-- All queries are static; signing/verification logic stays in the Service layer.

-- name: CreateCredential :one
INSERT INTO auth.credentials (tenant_id, subject, type, claims, expires_at, user_id)
VALUES (@tenant_id, @subject, @type, @claims, @expires_at, sqlc.narg('user_id'))
RETURNING id, issued_at;

-- IsOrganisationMember says whether the person belongs to the organisation:
-- holds a role in it, or has it as their home organisation.
-- name: IsOrganisationMember :one
SELECT (EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id)
     OR EXISTS (SELECT 1 FROM account.users u WHERE u.id = @user_id AND u.tenant_id = @tenant_id AND u.deleted_at IS NULL))::bool;

-- GetCredentialRevocation checks the revocation registry for a presented
-- JWT-VC (jti = credential id). The caller refuses a credential with no record.
-- name: GetCredentialRevocation :one
SELECT revoked_at FROM auth.credentials WHERE id = $1;

-- name: ListCredentials :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT c.id, c.subject, c.type, c.issued_at, c.expires_at, c.revoked_at,
       c.user_id, u.email AS user_email, u.display_name AS user_display_name
FROM auth.credentials c
LEFT JOIN account.users u ON u.id = c.user_id
WHERE c.tenant_id = $1 ORDER BY c.issued_at DESC LIMIT 1001;

-- name: RevokeCredential :execrows
UPDATE auth.credentials SET revoked_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL;
