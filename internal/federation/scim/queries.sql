-- Queries for the SCIM domain.
-- DYNAMIC queries kept hand-written:
--   listProvisioned  — conditional WHERE + dynamic parameter positions for LIMIT/OFFSET
--   listGroups       — same conditional pattern with optional name filter
--   touchGroupTx     — CASE WHEN bool flag controls external_id update

-- ==========================================================================
-- Token management
-- ==========================================================================

-- name: GetScimTokenConfig :one
SELECT token_prefix, created_at, last_used_at
FROM tenant.scim_tokens WHERE tenant_id = @tenant_id;

-- name: CountProvisionedUsers :one
SELECT count(*) FROM "user".users
WHERE tenant_id = @tenant_id AND provisioned_via = 'scim' AND deleted_at IS NULL;

-- name: UpsertScimToken :exec
INSERT INTO tenant.scim_tokens (tenant_id, token_hash, token_prefix, created_at, last_used_at)
VALUES (@tenant_id, @token_hash, @token_prefix, NOW(), NULL)
ON CONFLICT (tenant_id) DO UPDATE
    SET token_hash   = EXCLUDED.token_hash,
        token_prefix = EXCLUDED.token_prefix,
        created_at   = NOW(),
        last_used_at = NULL;

-- name: DeleteScimToken :execrows
DELETE FROM tenant.scim_tokens WHERE tenant_id = @tenant_id;

-- name: GetScimTokenTenant :one
SELECT tenant_id FROM tenant.scim_tokens WHERE token_hash = @token_hash;

-- name: TouchScimTokenUsed :exec
UPDATE tenant.scim_tokens SET last_used_at = NOW() WHERE tenant_id = @tenant_id;

-- ==========================================================================
-- Users (provisioned read + tag)
-- ==========================================================================

-- name: GetProvisionedUser :one
SELECT id, email, display_name, status, external_id, created_at, updated_at
FROM "user".users WHERE id = @id AND tenant_id = @tenant_id AND deleted_at IS NULL;

-- ProvisionedUserState is a user's status, what suspended them ('' when
-- not suspended), and whether they own the organisation, directly or through
-- a group; the row is locked for the change it decides.
-- name: ProvisionedUserState :one
SELECT u.status, COALESCE(u.suspension_source, '')::text AS suspension_source,
       EXISTS (
           SELECT 1 FROM rbac.user_roles ur
           JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.tenant_id = ur.tenant_id AND ro.is_system AND ro.name = 'owner'
           WHERE ur.user_id = u.id AND ur.tenant_id = @tenant_id
           UNION ALL
           SELECT 1 FROM tenant.group_members gm
           JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
           JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.tenant_id = gr.tenant_id AND ro.is_system AND ro.name = 'owner'
           WHERE gm.user_id = u.id AND gm.tenant_id = @tenant_id
       )::bool AS owner
FROM "user".users u
WHERE u.id = @id AND u.tenant_id = @tenant_id AND u.deleted_at IS NULL
FOR UPDATE OF u;

-- HomeUserByEmail finds a live account whose home is @tenant_id by its
-- address, whoever created it.
-- name: HomeUserByEmail :one
SELECT id FROM "user".users
WHERE tenant_id = @tenant_id::uuid AND LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: TagProvisionedUser :exec
UPDATE "user".users
    SET external_id    = sqlc.narg('external_id'),
        provisioned_via = 'scim',
        updated_at     = NOW()
WHERE id = @id;

-- ==========================================================================
-- Groups
-- ==========================================================================

-- name: GetScimGroup :one
SELECT id, name, external_id, created_at, updated_at
FROM tenant.groups WHERE id = @id AND tenant_id = @tenant_id AND provisioned_via = 'scim';

-- name: ListGroupMembers :many
SELECT gm.user_id, u.email, u.display_name
FROM tenant.group_members gm
JOIN "user".users u ON u.id = gm.user_id
WHERE gm.group_id = @group_id AND gm.tenant_id = @tenant_id AND u.deleted_at IS NULL
ORDER BY u.email;

-- name: InsertScimGroup :one
INSERT INTO tenant.groups (tenant_id, name, external_id, provisioned_via)
VALUES (@tenant_id, @name, sqlc.narg('external_id'), 'scim')
RETURNING id, name, external_id, created_at, updated_at;

-- name: DeleteGroupMembers :exec
DELETE FROM tenant.group_members WHERE group_id = @group_id AND tenant_id = @tenant_id;

-- name: RemoveGroupMember :exec
DELETE FROM tenant.group_members
WHERE group_id = @group_id AND user_id = @user_id AND tenant_id = @tenant_id;

-- name: DeleteScimGroup :execrows
DELETE FROM tenant.groups WHERE id = @id AND tenant_id = @tenant_id AND provisioned_via = 'scim';

-- name: CheckUserInTenant :one
SELECT EXISTS(
    SELECT 1 FROM "user".users WHERE id = @id AND tenant_id = @tenant_id AND deleted_at IS NULL
);

-- name: AddGroupMember :exec
INSERT INTO tenant.group_members (group_id, user_id, tenant_id)
VALUES (@group_id, @user_id, @tenant_id)
ON CONFLICT DO NOTHING;
