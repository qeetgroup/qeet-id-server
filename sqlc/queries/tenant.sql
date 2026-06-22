-- Pilot queries for the tenant domain. These mirror tenant/repository.go to
-- show the sqlc pattern (type-safe, compile-checked) the repos migrate onto.

-- name: GetTenant :one
SELECT id, slug, name, status, plan, region, metadata, created_at, updated_at
FROM tenant.tenants
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetTenantBySlug :one
SELECT id, slug, name, status, plan, region, metadata, created_at, updated_at
FROM tenant.tenants
WHERE lower(slug) = lower($1) AND deleted_at IS NULL;

-- name: ListTenantsForUser :many
SELECT t.id, t.slug, t.name, t.status, t.plan, t.region, t.metadata, t.created_at, t.updated_at
FROM tenant.tenants t
WHERE t.deleted_at IS NULL
  AND EXISTS (
    SELECT 1 FROM rbac.user_roles ur
    WHERE ur.tenant_id = t.id AND ur.user_id = $1
  )
ORDER BY t.created_at DESC, t.id DESC
LIMIT $2;
