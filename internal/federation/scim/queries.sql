-- Queries for the SCIM domain, compiled by sqlc into ./dbgen.

-- ==========================================================================
-- Token management
-- ==========================================================================

-- ListScimTokens is every token of the organization, newest first.
-- name: ListScimTokens :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by
FROM organization.scim_tokens
WHERE organization_id = @organization_id
ORDER BY created_at DESC, id DESC
LIMIT 1001;

-- name: CountProvisionedUsers :one
SELECT count(*) FROM account.users
WHERE organization_id = @organization_id AND provisioned_via = 'scim' AND deleted_at IS NULL;

-- CountLiveScimTokens counts the organization's tokens that work and haven't
-- been rotated: the ones the cap on creating tokens counts.
-- name: CountLiveScimTokens :one
SELECT count(*) FROM organization.scim_tokens
WHERE organization_id = @organization_id AND revoked_at IS NULL AND replaced_by IS NULL
  AND (expires_at IS NULL OR expires_at > NOW());

-- name: InsertScimToken :one
INSERT INTO organization.scim_tokens (organization_id, name, token_hash, token_prefix, expires_at, created_by)
VALUES (@organization_id, @name, @token_hash, @token_prefix, sqlc.narg('expires_at'),
        NULLIF(@created_by::uuid, '00000000-0000-0000-0000-000000000000'))
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- LockScimToken reads one of the organization's tokens and locks it for a
-- rotation.
-- name: LockScimToken :one
SELECT id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by
FROM organization.scim_tokens
WHERE id = @id AND organization_id = @organization_id
FOR UPDATE;

-- ReplaceScimToken records a token's rotation: it names its replacement and
-- works until the overlap ends, or stops now when there is none.
-- name: ReplaceScimToken :one
UPDATE organization.scim_tokens
SET replaced_by = @replaced_by,
    expires_at  = LEAST(expires_at, NOW() + make_interval(hours => sqlc.arg('overlap_hours')::int)),
    revoked_at  = CASE WHEN sqlc.arg('overlap_hours')::int = 0 THEN NOW() END
WHERE id = @id AND organization_id = @organization_id AND revoked_at IS NULL AND replaced_by IS NULL
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- name: RevokeScimToken :one
UPDATE organization.scim_tokens SET revoked_at = NOW()
WHERE id = @id AND organization_id = @organization_id AND revoked_at IS NULL
RETURNING id, name, token_prefix, created_at, expires_at, last_used_at, revoked_at, replaced_by;

-- RevokeLiveScimTokens stops every token of the organization that still
-- works, except the replacement when one is given, which it then names.
-- name: RevokeLiveScimTokens :execrows
UPDATE organization.scim_tokens
SET revoked_at = NOW(), replaced_by = COALESCE(replaced_by, sqlc.narg('replacement')::uuid)
WHERE organization_id = @organization_id AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > NOW())
  AND id IS DISTINCT FROM sqlc.narg('replacement')::uuid;

-- ResolveScimToken finds the token an identity provider presented, if it
-- works: not revoked or expired, of an organization that is active and not
-- due for deletion.
-- name: ResolveScimToken :one
SELECT t.id, t.organization_id, t.last_used_at
FROM organization.scim_tokens t
JOIN organization.organizations o ON o.id = t.organization_id
WHERE t.token_hash = @token_hash
  AND t.revoked_at IS NULL
  AND (t.expires_at IS NULL OR t.expires_at > NOW())
  AND o.status = 'active' AND o.deleted_at IS NULL AND o.deletion_due_at IS NULL;

-- TouchScimTokenUsed records a token's use, at most once a minute.
-- name: TouchScimTokenUsed :exec
UPDATE organization.scim_tokens SET last_used_at = NOW()
WHERE id = @id AND organization_id = @organization_id
  AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute');

-- ==========================================================================
-- Users (provisioned read + tag)
-- ==========================================================================

-- name: GetProvisionedUser :one
SELECT id, email, display_name, status, external_id, created_at, updated_at
FROM account.users WHERE id = @id AND organization_id = @organization_id AND deleted_at IS NULL;

-- ProvisionedUserState is a user's status, what suspended them ('' when
-- not suspended), and whether they own the organization, directly or through
-- a group; the row is locked for the change it decides.
-- name: ProvisionedUserState :one
SELECT u.status, COALESCE(u.suspension_source, '')::text AS suspension_source,
       EXISTS (
           SELECT 1 FROM rbac.user_roles ur
           JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id AND ro.is_system AND ro.name = 'owner'
           WHERE ur.user_id = u.id AND ur.organization_id = @organization_id
           UNION ALL
           SELECT 1 FROM organization.group_members gm
           JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
           JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id AND ro.is_system AND ro.name = 'owner'
           WHERE gm.user_id = u.id AND gm.organization_id = @organization_id
       )::bool AS owner
FROM account.users u
WHERE u.id = @id AND u.organization_id = @organization_id AND u.deleted_at IS NULL
FOR UPDATE OF u;

-- HomeUserByEmail finds a live account whose home is @organization_id by its
-- address, whoever created it.
-- name: HomeUserByEmail :one
SELECT id FROM account.users
WHERE organization_id = @organization_id::uuid AND LOWER(email) = LOWER(@email) AND deleted_at IS NULL;

-- name: TagProvisionedUser :exec
UPDATE account.users
    SET external_id    = sqlc.narg('external_id'),
        provisioned_via = 'scim',
        updated_at     = NOW()
WHERE id = @id;

-- The SCIM protocol's user list pages by offset, newest first: the
-- organization's provisioned users, or a userName lookup of any account at
-- home there.

-- name: ListProvisionedUsers :many
SELECT id, email, display_name, status, external_id, created_at, updated_at
FROM account.users
WHERE organization_id = @organization_id AND deleted_at IS NULL AND provisioned_via = 'scim'
ORDER BY created_at DESC, id DESC
LIMIT @lim::bigint OFFSET @off::bigint;

-- name: CountHomeUsersByEmail :one
SELECT count(*) FROM account.users
WHERE organization_id = @organization_id AND deleted_at IS NULL AND LOWER(email) = LOWER(@email);

-- name: ListHomeUsersByEmail :many
SELECT id, email, display_name, status, external_id, created_at, updated_at
FROM account.users
WHERE organization_id = @organization_id AND deleted_at IS NULL AND LOWER(email) = LOWER(@email)
ORDER BY created_at DESC, id DESC
LIMIT @lim::bigint OFFSET @off::bigint;

-- ListProvisionedUsersPage is a console page of the provisioned users, newest
-- first, before the cursor (created_at, id) when before_ts is set.
-- name: ListProvisionedUsersPage :many
SELECT id, email, display_name, status, external_id, created_at
FROM account.users
WHERE organization_id = @organization_id AND deleted_at IS NULL AND provisioned_via = 'scim'
  AND (sqlc.narg('before_ts')::timestamptz IS NULL OR created_at < sqlc.narg('before_ts')
       OR (created_at = sqlc.narg('before_ts') AND id < sqlc.narg('before_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: SetProvisionedUserEmail :exec
-- The directory vouches for the address it gives.
UPDATE account.users SET email = @email, email_verified_at = NOW(), updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id;

-- name: SetScimSuspension :exec
UPDATE account.users SET suspension_source = 'scim', suspension_reason = 'provider'
WHERE organization_id = @organization_id AND id = @id;

-- name: ClaimUnattributedSuspension :exec
-- A suspension nothing else claimed becomes the directory's.
UPDATE account.users SET suspension_source = 'scim', suspension_reason = 'provider'
WHERE organization_id = @organization_id AND id = @id AND suspension_source = 'unknown';

-- ==========================================================================
-- Groups
-- ==========================================================================

-- name: CountScimGroups :one
-- An empty name counts every group SCIM made.
SELECT count(*) FROM organization.groups
WHERE organization_id = @organization_id AND provisioned_via = 'scim'
  AND (@name::text = '' OR LOWER(name) = LOWER(@name));

-- name: ListScimGroups :many
SELECT id, name, external_id, created_at, updated_at
FROM organization.groups
WHERE organization_id = @organization_id AND provisioned_via = 'scim'
  AND (@name::text = '' OR LOWER(name) = LOWER(@name))
ORDER BY created_at DESC, id DESC
LIMIT @lim::bigint OFFSET @off::bigint;

-- ListScimGroupsPage is a console page of the groups SCIM made, newest first,
-- each with its count of live members, before the cursor when before_ts is set.
-- name: ListScimGroupsPage :many
SELECT g.id, g.name, g.external_id, g.created_at, g.updated_at,
       (SELECT count(*) FROM organization.group_members gm JOIN account.users u ON u.id = gm.user_id
        WHERE gm.group_id = g.id AND gm.organization_id = g.organization_id AND u.deleted_at IS NULL)::int AS members
FROM organization.groups g
WHERE g.organization_id = @organization_id AND g.provisioned_via = 'scim'
  AND (sqlc.narg('before_ts')::timestamptz IS NULL OR g.created_at < sqlc.narg('before_ts')
       OR (g.created_at = sqlc.narg('before_ts') AND g.id < sqlc.narg('before_id')::uuid))
ORDER BY g.created_at DESC, g.id DESC
LIMIT @lim;

-- name: TouchScimGroup :execrows
-- Sets the name when given, the external ID when set_external_id (NULL clears
-- it), and bumps updated_at.
UPDATE organization.groups SET
    name        = COALESCE(sqlc.narg('name'), name),
    external_id = CASE WHEN @set_external_id::bool THEN sqlc.narg('external_id') ELSE external_id END,
    updated_at  = NOW()
WHERE id = @id AND organization_id = @organization_id AND provisioned_via = 'scim';

-- name: GetScimGroup :one
SELECT id, name, external_id, created_at, updated_at
FROM organization.groups WHERE id = @id AND organization_id = @organization_id AND provisioned_via = 'scim';

-- name: ListGroupMembers :many
SELECT gm.user_id, u.email, u.display_name
FROM organization.group_members gm
JOIN account.users u ON u.id = gm.user_id
WHERE gm.group_id = @group_id AND gm.organization_id = @organization_id AND u.deleted_at IS NULL
ORDER BY u.email;

-- name: InsertScimGroup :one
INSERT INTO organization.groups (organization_id, name, external_id, provisioned_via)
VALUES (@organization_id, @name, sqlc.narg('external_id'), 'scim')
RETURNING id, name, external_id, created_at, updated_at;

-- name: DeleteGroupMembers :exec
DELETE FROM organization.group_members WHERE group_id = @group_id AND organization_id = @organization_id;

-- name: RemoveGroupMember :exec
DELETE FROM organization.group_members
WHERE group_id = @group_id AND user_id = @user_id AND organization_id = @organization_id;

-- name: DeleteScimGroup :execrows
DELETE FROM organization.groups WHERE id = @id AND organization_id = @organization_id AND provisioned_via = 'scim';

-- name: CheckUserInOrganization :one
SELECT EXISTS(
    SELECT 1 FROM account.users WHERE id = @id AND organization_id = @organization_id AND deleted_at IS NULL
);

-- AddGroupMember makes a membership a single sign-on made the directory's, so
-- the person's sign-ins no longer remove it.
-- name: AddGroupMember :exec
INSERT INTO organization.group_members AS gm (group_id, user_id, organization_id)
VALUES (@group_id, @user_id, @organization_id)
ON CONFLICT (group_id, user_id) DO UPDATE SET source_connection_id = NULL
WHERE gm.organization_id = EXCLUDED.organization_id AND gm.source_connection_id IS NOT NULL;

-- LastSCIMOperation returns the last change the organization's identity
-- provider sent, as its directory event recorded it.
-- name: LastSCIMOperation :one
SELECT started_at, operation, resource_type, http_status, status, error_code, reason
FROM organization.directory_events
WHERE organization_id = @organization_id AND connection_id = @connection_id
ORDER BY started_at DESC, id DESC
LIMIT 1;
