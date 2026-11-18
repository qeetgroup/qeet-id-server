-- Queries for the service-accounts (principal) domain.

-- name: CreateServicePrincipal :one
INSERT INTO auth.service_principals (organization_id, name, description, secret_hash, scopes, created_by)
VALUES (@organization_id, @name, @description, @secret_hash, @scopes, sqlc.narg('created_by'))
RETURNING id, organization_id, name, scopes, disabled_at, created_at, description;

-- name: ListServicePrincipals :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, name, scopes, disabled_at, created_at, description, last_used_at, previous_secret_expires_at
FROM auth.service_principals WHERE organization_id = $1 ORDER BY created_at DESC
LIMIT 1001;

-- DisableServicePrincipal marks the principal disabled, returning its name for
-- the audit row.
-- name: DisableServicePrincipal :one
UPDATE auth.service_principals SET disabled_at = NOW()
WHERE id = $1 AND organization_id = $2 AND disabled_at IS NULL
RETURNING name;

-- PrincipalLive is whether a principal is enabled, in an active
-- organization: no row for one of a suspended or deleted organization.
-- name: PrincipalLive :one
SELECT (p.disabled_at IS NULL)::bool AS live FROM auth.service_principals p
JOIN organization.organizations t ON t.id = p.organization_id AND t.status = 'active' AND t.deleted_at IS NULL
WHERE p.id = $1;

-- GetServicePrincipalForAuth is the credential row the client_credentials
-- grant (ClientCredentials) verifies a secret against, never returned to the
-- caller. It finds no principal of a suspended or deleted organization.
-- name: GetServicePrincipalForAuth :one
SELECT p.id, p.organization_id, p.secret_hash, p.scopes, p.disabled_at, p.previous_secret_hash, p.previous_secret_expires_at
FROM auth.service_principals p
JOIN organization.organizations t ON t.id = p.organization_id AND t.status = 'active' AND t.deleted_at IS NULL
WHERE p.id = $1;

-- TouchServicePrincipal notes a token issued to the principal, at most once
-- a minute.
-- name: TouchServicePrincipal :exec
UPDATE auth.service_principals SET last_used_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute');

-- RotateServicePrincipalSecret makes the new secret current and keeps the
-- old one working until previous_expires_at.
-- name: RotateServicePrincipalSecret :one
UPDATE auth.service_principals
SET previous_secret_hash = secret_hash, previous_secret_expires_at = @previous_expires_at, secret_hash = @secret_hash
WHERE id = @id AND organization_id = @organization_id
RETURNING name;

-- name: EnableServicePrincipal :one
UPDATE auth.service_principals SET disabled_at = NULL
WHERE id = @id AND organization_id = @organization_id
RETURNING name;

-- ServicePrincipalScopes returns the scopes of one of the organization's service principals.
-- name: ServicePrincipalScopes :one
SELECT scopes FROM auth.service_principals WHERE id = @id AND organization_id = @organization_id;
