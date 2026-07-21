-- Queries for the service-accounts (principal) domain.
-- Create and Disable accept a pgx.Tx from the handler so audit can share the
-- transaction; the sqlc queries are called via q.WithTx(tx).

-- name: CreateServicePrincipal :one
INSERT INTO auth.service_principals (tenant_id, name, description, secret_hash, scopes)
VALUES (@tenant_id, @name, @description, @secret_hash, @scopes)
RETURNING id, tenant_id, name, scopes, disabled_at, created_at;

-- name: ListServicePrincipals :many
SELECT id, tenant_id, name, scopes, disabled_at, created_at
FROM auth.service_principals WHERE tenant_id = $1 ORDER BY created_at DESC;

-- DisableServicePrincipal marks the principal disabled. RETURNING tenant_id
-- and name so the caller can write the audit row without a second query.
-- name: DisableServicePrincipal :one
UPDATE auth.service_principals SET disabled_at = NOW()
WHERE id = $1 AND disabled_at IS NULL
RETURNING tenant_id, name;

-- GetServicePrincipalForAuth fetches the full credential row for the
-- client_credentials grant (IssueClientCredentials). Includes secret_hash
-- for argon2/bcrypt verification — never returned to the API caller.
-- name: GetServicePrincipalForAuth :one
SELECT id, tenant_id, secret_hash, scopes, disabled_at
FROM auth.service_principals WHERE id = $1;
