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
