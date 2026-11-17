-- Queries for the SCIM domain.
-- DYNAMIC queries kept hand-written:
--   listProvisioned  — conditional WHERE + dynamic parameter positions for LIMIT/OFFSET
--   listGroups       — same conditional pattern with optional name filter
--   touchGroupTx     — CASE WHEN bool flag controls external_id update

-- ==========================================================================
-- Token management
-- ==========================================================================

-- ListScimTokens is every token of the organisation, newest first.
-- name: ListScimTokens :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by
FROM tenant.scim_tokens
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC, id DESC
LIMIT 1001;

-- name: CountProvisionedUsers :one
SELECT count(*) FROM "user".users
WHERE tenant_id = @tenant_id AND provisioned_via = 'scim' AND deleted_at IS NULL;

-- CountLiveScimTokens counts the organisation's tokens that work and haven't
-- been rotated: the ones the cap on creating tokens counts.
-- name: CountLiveScimTokens :one
SELECT count(*) FROM tenant.scim_tokens
WHERE tenant_id = @tenant_id AND revoked_at IS NULL AND replaced_by IS NULL
  AND (expires_at IS NULL OR expires_at > NOW());

-- name: InsertScimToken :one
INSERT INTO tenant.scim_tokens (tenant_id, name, token_hash, token_prefix, expires_at, created_by)
VALUES (@tenant_id, @name, @token_hash, @token_prefix, sqlc.narg('expires_at'),
        NULLIF(@created_by::uuid, '00000000-0000-0000-0000-000000000000'))
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- LockScimToken reads one of the organisation's tokens and locks it for a
-- rotation.
-- name: LockScimToken :one
SELECT id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by
FROM tenant.scim_tokens
WHERE id = @id AND tenant_id = @tenant_id
FOR UPDATE;

-- ReplaceScimToken records a token's rotation: it names its replacement and
-- works until the overlap ends, or stops now when there is none.
-- name: ReplaceScimToken :one
UPDATE tenant.scim_tokens
SET replaced_by = @replaced_by,
    expires_at  = LEAST(expires_at, NOW() + make_interval(hours => sqlc.arg('overlap_hours')::int)),
    revoked_at  = CASE WHEN sqlc.arg('overlap_hours')::int = 0 THEN NOW() END
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL AND replaced_by IS NULL
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- name: RevokeScimToken :one
UPDATE tenant.scim_tokens SET revoked_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id AND revoked_at IS NULL
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- RevokeLiveScimTokens stops every token of the organisation that still
-- works, except the replacement when one is given, which it then names.
-- name: RevokeLiveScimTokens :execrows
UPDATE tenant.scim_tokens
SET revoked_at = NOW(), replaced_by = COALESCE(replaced_by, sqlc.narg('replacement')::uuid)
WHERE tenant_id = @tenant_id AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
  AND id IS DISTINCT FROM sqlc.narg('replacement')::uuid;

-- ResolveScimToken finds the token an identity provider presented, if it
-- works: not revoked or expired, of an organisation that is active and not
-- due for deletion.
-- name: ResolveScimToken :one
SELECT t.id, t.tenant_id, t.last_used_at
FROM tenant.scim_tokens t
JOIN tenant.tenants o ON o.id = t.tenant_id
WHERE t.token_hash = @token_hash
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > NOW())
  AND o.status = 'active' AND o.deleted_at IS NULL AND o.deletion_due_at IS NULL;

-- TouchScimTokenUsed records a token's use, at most once a minute.
-- name: TouchScimTokenUsed :exec
UPDATE tenant.scim_tokens SET last_used_at = NOW()
WHERE id = @id AND tenant_id = @tenant_id
  AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute');

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

-- AddGroupMember makes a membership a single sign-on made the directory's, so
-- the person's sign-ins no longer remove it.
-- name: AddGroupMember :exec
INSERT INTO tenant.group_members AS gm (group_id, user_id, tenant_id)
VALUES (@group_id, @user_id, @tenant_id)
ON CONFLICT (group_id, user_id) DO UPDATE SET source_connection_id = NULL
WHERE gm.tenant_id = EXCLUDED.tenant_id AND gm.source_connection_id IS NOT NULL;

-- LastSCIMOperation returns the last change the organisation's identity
-- provider sent, as its directory event recorded it.
-- name: LastSCIMOperation :one
SELECT started_at, operation, resource_type, http_status, status, error_code, reason
FROM tenant.directory_events
WHERE tenant_id = @tenant_id AND connection_id = @connection_id
ORDER BY started_at DESC, id DESC
LIMIT 1;
