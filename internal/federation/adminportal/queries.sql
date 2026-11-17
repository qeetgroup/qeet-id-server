-- Queries for the adminportal domain.
-- Static queries against organization.admin_portal_links and organization.organizations are compiled
-- by sqlc into ./dbgen. Dynamic/complex logic stays hand-written in adminportal.go.

-- name: InsertAdminPortalLink :one
INSERT INTO organization.admin_portal_links (organization_id, token_hash, capabilities, created_by, expires_at)
VALUES (@organization_id, @token_hash, @capabilities, @created_by, @expires_at)
RETURNING id, organization_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at;

-- name: ListAdminPortalLinksByOrganization :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at
FROM organization.admin_portal_links
WHERE organization_id = @organization_id ORDER BY created_at DESC
LIMIT 1001;

-- name: RevokeAdminPortalLink :execrows
UPDATE organization.admin_portal_links SET revoked_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND revoked_at IS NULL;

-- name: GetAdminPortalLinkByHash :one
SELECT id, organization_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at
FROM organization.admin_portal_links WHERE token_hash = @token_hash;

-- name: TouchAdminPortalLinkUsed :exec
UPDATE organization.admin_portal_links SET last_used_at = NOW() WHERE id = @id;

-- name: GetOrganizationNameByID :one
SELECT name FROM organization.organizations WHERE id = @id;
