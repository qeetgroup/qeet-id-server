-- Queries for the provision domain: the account a federated sign-in (SAML,
-- LDAP, OpenID Connect single sign-on, social) names, found by its link,
-- adopted by its address or created, and the link itself. All queries are
-- STATIC.

-- LinkedAccount returns the account the provider's subject is linked to
-- through the connection, or, for a social provider (no connection), through
-- that provider alone: a connection's links are never a social provider's,
-- whatever it is named.
-- name: LinkedAccount :one
SELECT user_id FROM account.external_identities
WHERE organization_id = @organization_id AND provider = @provider AND subject = @subject
  AND connection_id IS NOT DISTINCT FROM sqlc.narg('connection_id')::uuid;

-- name: AccountByEmail :one
SELECT id FROM account.users WHERE LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: InsertAccount :one
INSERT INTO account.users (organization_id, email, email_verified_at, display_name, status)
VALUES (@organization_id, @email, CASE WHEN @verified::bool THEN NOW() END, sqlc.narg('display_name'), 'active')
RETURNING id;

-- Link links the subject to the account, or refreshes the address and
-- profile its link holds; a nil metadata keeps the profile it holds.
-- name: Link :exec
INSERT INTO account.external_identities (user_id, organization_id, provider, connection_id, subject, email, metadata)
VALUES (@user_id, @organization_id, @provider, sqlc.narg('connection_id')::uuid, @subject, sqlc.narg('email'),
        COALESCE(sqlc.narg('metadata')::jsonb, '{}'::jsonb))
ON CONFLICT (organization_id, provider, connection_id, subject) DO UPDATE
SET email = EXCLUDED.email, metadata = COALESCE(sqlc.narg('metadata')::jsonb, account.external_identities.metadata)
WHERE account.external_identities.user_id = EXCLUDED.user_id;

-- name: SuspendDirectoryAccount :execrows
UPDATE account.users SET status = 'suspended', updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id::uuid AND deleted_at IS NULL AND status <> 'suspended';

-- Only the directory that claimed a suspension lifts it.
-- name: ClaimDirectorySuspension :exec
UPDATE account.users SET suspension_source = @source::text, suspension_reason = 'provider'
WHERE id = @id AND organization_id = @organization_id::uuid AND status = 'suspended' AND suspension_source = 'unknown';
