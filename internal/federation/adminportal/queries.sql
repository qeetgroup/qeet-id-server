-- Queries for the adminportal domain, compiled by sqlc into ./dbgen.

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

-- name: LockAdminPortalLinkByHash :one
-- The link a one-time token names, locked so concurrent redemption has one
-- winner.
SELECT id, organization_id, capabilities, created_by, expires_at, revoked_at, last_used_at, created_at, redeemed_at
FROM organization.admin_portal_links WHERE token_hash = @token_hash
FOR UPDATE;

-- name: MarkAdminPortalLinkRedeemed :exec
UPDATE organization.admin_portal_links SET redeemed_at = NOW(), last_used_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- name: InsertAdminPortalSession :exec
INSERT INTO auth.admin_portal_sessions (link_id, token_hash, expires_at)
VALUES (@link_id, @token_hash, @expires_at);

-- name: GetAdminPortalSessionByHash :one
-- A portal session with its link, by the session cookie's hash.
SELECT s.id AS session_id, s.expires_at AS session_expires_at, s.revoked_at AS session_revoked_at,
       l.id, l.organization_id, l.capabilities, l.created_by, l.expires_at,
       l.revoked_at, l.last_used_at, l.created_at
FROM auth.admin_portal_sessions s
JOIN organization.admin_portal_links l ON l.id = s.link_id
WHERE s.token_hash = @token_hash;

-- name: TouchAdminPortalSession :exec
UPDATE auth.admin_portal_sessions SET last_used_at = NOW() WHERE id = @id;

-- name: RevokeAdminPortalSession :execrows
UPDATE auth.admin_portal_sessions SET revoked_at = NOW()
WHERE token_hash = @token_hash AND revoked_at IS NULL;

-- name: GetOrganizationNameByID :one
SELECT name FROM organization.organizations WHERE id = @id;
