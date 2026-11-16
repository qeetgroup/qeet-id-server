-- Queries for the service-accounts (principal) domain.
-- Create and Disable accept a pgx.Tx from the handler so audit can share the
-- transaction; the sqlc queries are called via q.WithTx(tx).

-- name: CreateServicePrincipal :one
INSERT INTO auth.service_principals (tenant_id, name, description, secret_hash, scopes)
VALUES (@tenant_id, @name, @description, @secret_hash, @scopes)
RETURNING id, tenant_id, name, scopes, disabled_at, created_at, description;

-- name: ListServicePrincipals :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, name, scopes, disabled_at, created_at, description, last_used_at, previous_secret_expires_at
FROM auth.service_principals WHERE tenant_id = $1 ORDER BY created_at DESC
LIMIT 1001;

-- DisableServicePrincipal marks the principal disabled. RETURNING tenant_id
-- and name so the caller can write the audit row without a second query.
-- name: DisableServicePrincipal :one
UPDATE auth.service_principals SET disabled_at = NOW()
WHERE id = $1 AND tenant_id = $2 AND disabled_at IS NULL
RETURNING tenant_id, name;

-- GetServicePrincipalForAuth fetches the full credential row for the
-- client_credentials grant (IssueClientCredentials). Includes secret_hash
-- for argon2/bcrypt verification — never returned to the API caller.
-- PrincipalLive reports whether a service principal exists and isn't
-- disabled. No row: it doesn't exist.
-- name: PrincipalLive :one
SELECT (disabled_at IS NULL)::bool AS live FROM auth.service_principals WHERE id = $1;

-- name: GetServicePrincipalForAuth :one
SELECT id, tenant_id, secret_hash, scopes, disabled_at, previous_secret_hash, previous_secret_expires_at
FROM auth.service_principals WHERE id = $1;

-- TouchServicePrincipal notes a token issued to the principal, at most once
-- a minute.
-- name: TouchServicePrincipal :exec
UPDATE auth.service_principals SET last_used_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute');

-- RotateServicePrincipalSecret makes the new secret current and keeps the
-- old one working until previous_expires_at.
-- name: RotateServicePrincipalSecret :one
UPDATE auth.service_principals
SET previous_secret_hash = secret_hash, previous_secret_expires_at = @previous_expires_at, secret_hash = @secret_hash
WHERE id = @id AND tenant_id = @tenant_id
RETURNING name;

-- name: EnableServicePrincipal :one
UPDATE auth.service_principals SET disabled_at = NULL
WHERE id = @id AND tenant_id = @tenant_id
RETURNING name;

-- UpgradeServicePrincipalSecretHash replaces an Argon2id secret hash from before
-- with its SHA-256 form, once the secret has verified.
-- name: UpgradeServicePrincipalSecretHash :exec
UPDATE auth.service_principals SET secret_hash = @new_hash
WHERE id = @id AND tenant_id = @tenant_id AND secret_hash = @old_hash;
