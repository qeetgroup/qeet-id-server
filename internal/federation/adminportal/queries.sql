-- Queries for the adminportal domain.
-- Static queries against tenant.admin_portal_links and tenant.tenants are compiled
-- by sqlc into ./dbgen. Dynamic/complex logic stays hand-written in adminportal.go.

-- name: InsertAdminPortalLink :one
INSERT INTO tenant.admin_portal_links (tenant_id, token_hash, capabilities, created_by, expires_at)
VALUES (@tenant_id, @token_hash, @capabilities, @created_by, @expires_at)
RETURNING id, tenant_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at;

-- name: ListAdminPortalLinksByTenant :many
SELECT id, tenant_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at
FROM tenant.admin_portal_links
WHERE tenant_id = @tenant_id ORDER BY created_at DESC;

-- name: RevokeAdminPortalLink :execrows
UPDATE tenant.admin_portal_links SET revoked_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL;

-- name: GetAdminPortalLinkByHash :one
SELECT id, tenant_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at
FROM tenant.admin_portal_links WHERE token_hash = @token_hash;

-- name: TouchAdminPortalLinkUsed :exec
UPDATE tenant.admin_portal_links SET last_used_at = NOW() WHERE id = @id;

-- name: GetTenantNameByID :one
SELECT name FROM tenant.tenants WHERE id = @id;
