-- Queries for the domain-verification domain.
-- All queries are static. Error handling for the unique-index violations
-- (uq_tenant_domain, uq_verified_domain) stays in the service layer via
-- strings.Contains checks preserved in domainverify.go.

-- name: InsertDomain :one
INSERT INTO tenant.domains (tenant_id, domain, verification_token)
VALUES ($1, $2, $3)
RETURNING id, domain, verification_token, verified_at, created_at;

-- name: ListDomains :many
SELECT id, domain, verification_token, verified_at, created_at
FROM tenant.domains WHERE tenant_id = $1 ORDER BY created_at DESC;

-- name: GetDomainForVerify :one
SELECT id, domain, verification_token, verified_at, created_at
FROM tenant.domains WHERE id = $1 AND tenant_id = $2;

-- name: MarkDomainVerified :one
UPDATE tenant.domains SET verified_at = NOW()
WHERE id = $1 AND tenant_id = $2
RETURNING id, domain, verification_token, verified_at, created_at;

-- name: DeleteDomain :execrows
DELETE FROM tenant.domains WHERE id = $1 AND tenant_id = $2;

-- EmailDomainManager returns the organisation managing accounts on @domain:
-- the one that verified it, or the closest domain above it. @domain is
-- lower-case.
-- name: EmailDomainManager :one
SELECT d.tenant_id
FROM tenant.domains d
WHERE d.verified_at IS NOT NULL
  AND (lower(d.domain) = @domain::text
       OR right(@domain::text, length(d.domain) + 1) = '.' || lower(d.domain))
ORDER BY length(d.domain) DESC
LIMIT 1;

-- name: GetLoginDomainCheck :one
SELECT host, checked_at, result FROM tenant.login_domain_checks WHERE tenant_id = @tenant_id;

-- name: SaveLoginDomainCheck :exec
INSERT INTO tenant.login_domain_checks (tenant_id, host, checked_at, result)
VALUES (@tenant_id, @host, @checked_at, @result)
ON CONFLICT (tenant_id) DO UPDATE
SET host = EXCLUDED.host, checked_at = EXCLUDED.checked_at, result = EXCLUDED.result;
