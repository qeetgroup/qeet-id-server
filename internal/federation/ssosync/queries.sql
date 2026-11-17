-- Queries for the ssosync domain: what a SAML or LDAP sign-in refreshes on
-- the account it signs in (ssosync.go), and the group mappings an
-- administrator sets per connection (mapping.go). All queries are STATIC.

-- ==========================================================================
-- Profile refresh
-- ==========================================================================

-- name: GetAccountProfile :one
SELECT email, display_name FROM account.users
WHERE id = @id AND organization_id = @organization_id::uuid AND deleted_at IS NULL
FOR UPDATE;

-- name: SetDisplayName :exec
UPDATE account.users SET display_name = @display_name, updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id::uuid;

-- name: SetEmail :exec
UPDATE account.users SET email = @email, email_verified_at = NOW(), updated_at = NOW()
WHERE id = @id AND organization_id = @organization_id::uuid;

-- ==========================================================================
-- Group sync
-- ==========================================================================

-- SyncTargets returns the groups the asserted values reach, compared ignoring
-- case: through one of the connection's mappings, or as the external id of a
-- group SCIM made. A group whose roles carry the owner role or a permission
-- outside member_permissions is left out.
-- name: SyncTargets :many
WITH asserted AS (
    SELECT DISTINCT lower(v) AS value FROM unnest(@idp_groups::text[]) AS v
)
SELECT g.id FROM organization.groups g
WHERE g.organization_id = @organization_id
  AND (
      EXISTS (
          SELECT 1 FROM organization.sso_group_mappings m
          JOIN asserted a ON a.value = lower(m.idp_group)
          WHERE m.organization_id = g.organization_id AND m.group_id = g.id AND m.connection_id = @connection_id
      )
      OR (g.provisioned_via = 'scim' AND lower(g.external_id) IN (SELECT value FROM asserted))
  )
  AND NOT EXISTS (
      SELECT 1 FROM rbac.group_roles gr
      JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
      LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
      LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
      WHERE gr.organization_id = g.organization_id AND gr.group_id = g.id
        AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[]))))
  )
ORDER BY g.id;

-- name: SyncedMemberships :many
SELECT group_id FROM organization.group_members
WHERE organization_id = @organization_id AND user_id = @user_id AND source_connection_id = @connection_id::uuid
ORDER BY group_id;

-- AddSyncedMembership adds the person to the group as the connection's, and
-- leaves a membership they already have as it is.
-- name: AddSyncedMembership :execrows
INSERT INTO organization.group_members (group_id, user_id, organization_id, source_connection_id)
VALUES (@group_id, @user_id, @organization_id, @connection_id::uuid)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveSyncedMembership :execrows
DELETE FROM organization.group_members
WHERE organization_id = @organization_id AND group_id = @group_id AND user_id = @user_id
  AND source_connection_id = @connection_id::uuid;

-- ==========================================================================
-- Group mappings
-- ==========================================================================

-- name: SAMLConnectionExists :one
SELECT EXISTS (SELECT 1 FROM organization.saml_connections WHERE id = @id AND organization_id = @organization_id);

-- name: LDAPConnectionExists :one
SELECT EXISTS (SELECT 1 FROM organization.ldap_connections WHERE id = @id AND organization_id = @organization_id);

-- GroupPrivileged returns no row for a group that isn't the organization's, else its
-- name and whether its roles carry the owner role or a permission outside
-- member_permissions.
-- name: GroupPrivileged :one
SELECT g.name, EXISTS (
    SELECT 1 FROM rbac.group_roles gr
    JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
    LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
    LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gr.organization_id = g.organization_id AND gr.group_id = g.id
      AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[]))))
) AS privileged
FROM organization.groups g WHERE g.id = @group_id AND g.organization_id = @organization_id;

-- name: ListGroupMappings :many
SELECT m.id, m.idp_group, m.group_id, g.name AS group_name, m.created_at
FROM organization.sso_group_mappings m
JOIN organization.groups g ON g.organization_id = m.organization_id AND g.id = m.group_id
WHERE m.organization_id = @organization_id AND m.connection_id = @connection_id
ORDER BY lower(m.idp_group), g.name, m.id;

-- name: CountGroupMappings :one
SELECT count(*) FROM organization.sso_group_mappings
WHERE organization_id = @organization_id AND connection_id = @connection_id;

-- name: InsertGroupMapping :one
INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id)
VALUES (@organization_id, @connection_id, @idp_group, @group_id)
RETURNING id, created_at;

-- name: DeleteGroupMapping :one
DELETE FROM organization.sso_group_mappings
WHERE id = @id AND organization_id = @organization_id AND connection_id = @connection_id
RETURNING idp_group, group_id;

-- RemoveUnmappedMemberships removes the memberships of the group the
-- connection's sign-ins made once none of its mappings reaches the group.
-- name: RemoveUnmappedMemberships :many
DELETE FROM organization.group_members gm
WHERE gm.organization_id = @organization_id AND gm.group_id = @group_id AND gm.source_connection_id = @connection_id::uuid
  AND NOT EXISTS (
      SELECT 1 FROM organization.sso_group_mappings m
      WHERE m.organization_id = gm.organization_id AND m.group_id = gm.group_id AND m.connection_id = @connection_id::uuid
  )
RETURNING gm.user_id;
