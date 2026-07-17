-- Queries for the organizations (tenant) domain.
-- Static queries against tenant.tenants live here and are compiled by sqlc into ./dbgen.
-- Dynamic queries (partial UPDATE) intentionally remain hand-written in repository.go.

-- name: GetTenant :one
SELECT * FROM tenant.tenants
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetTenantBySlug :one
SELECT * FROM tenant.tenants
WHERE LOWER(slug) = LOWER(@slug) AND deleted_at IS NULL;

-- name: InsertTenant :one
INSERT INTO tenant.tenants (slug, name, plan, region, metadata)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: SoftDeleteTenant :execrows
UPDATE tenant.tenants
SET deleted_at = NOW(), status = 'deleted', updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL;

-- List the tenants a user is a member of, newest first. Cursor pagination is split
-- into a first-page and after-cursor variant (the idiomatic sqlc way to do dynamic paging).

-- name: ListTenantsForUser :many
SELECT * FROM tenant.tenants
WHERE deleted_at IS NULL
  AND EXISTS (
    SELECT 1 FROM rbac.user_roles ur
    WHERE ur.tenant_id = tenant.tenants.id AND ur.user_id = $1
  )
ORDER BY created_at DESC, id DESC
LIMIT $2;

-- name: ListTenantsForUserAfter :many
SELECT * FROM tenant.tenants
WHERE deleted_at IS NULL
  AND EXISTS (
    SELECT 1 FROM rbac.user_roles ur
    WHERE ur.tenant_id = tenant.tenants.id AND ur.user_id = $1
  )
  AND (created_at < @before_created_at
       OR (created_at = @before_created_at AND id < @before_id))
ORDER BY created_at DESC, id DESC
LIMIT @row_limit;
