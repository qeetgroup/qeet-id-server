-- Queries for the rbac domain. All queries are sqlc-generated, including the two
-- awkward ones: AssignRoleToGroup (a conditional CTE INSERT whose RETURNING is
-- folded into an EXISTS check, returning a single bool) and ExplainGrants (a
-- two-armed UNION ALL with typed NULL columns for the direct arm).

-- name: UpsertPermission :one
INSERT INTO rbac.permissions (key, description)
VALUES (@key, @description)
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description
RETURNING id, key, description;

-- name: GrantBuiltinRolePermissions :exec
-- Every organization's built-in roles hold what their definitions cover of the
-- catalogue as it is now: owner everything, admin everything but deleting the
-- organization, viewer every read but secrets' (whose read reveals them).
INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT ro.id, p.id
FROM rbac.roles ro
JOIN rbac.permissions p ON ro.name = 'owner'
                        OR (ro.name = 'admin' AND p.key <> 'tenant.delete')
                        OR (ro.name = 'viewer' AND p.key LIKE '%.read' AND p.key <> 'secret.read')
WHERE ro.is_system
ON CONFLICT DO NOTHING;

-- name: ListPermissions :many
SELECT id, key, description FROM rbac.permissions ORDER BY key;

-- name: GetPermissionKey :one
SELECT key FROM rbac.permissions WHERE id = @id;

-- name: CreateRole :one
INSERT INTO rbac.roles (organization_id, name, description, is_system)
VALUES (@organization_id, @name, @description, @is_system)
RETURNING id, organization_id, name, description, is_system, created_at;

-- name: ListRoles :many
SELECT id, organization_id, name, description, is_system, created_at
FROM rbac.roles
WHERE organization_id = @organization_id
ORDER BY name;

-- CountCustomRoles counts an organization's non-system (custom) roles — the plan-limit
-- check. Built-in roles (is_system = TRUE) don't count toward the cap.
-- name: CountCustomRoles :one
SELECT COUNT(*) FROM rbac.roles
WHERE organization_id = @organization_id AND is_system = FALSE;

-- name: GetRoleOrganization :one
SELECT organization_id FROM rbac.roles WHERE id = @id;

-- name: ListRolePermissions :many
SELECT p.id, p.key, p.description
FROM rbac.permissions p
JOIN rbac.role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = @role_id
ORDER BY p.key;

-- LockRole reads a role of the organization for a change, held until it commits, so
-- nobody gives the role to anyone or edits it meanwhile.
-- name: LockRole :one
SELECT id, organization_id, name, description, is_system, created_at
FROM rbac.roles WHERE id = @id AND organization_id = @organization_id
FOR UPDATE;

-- name: PermissionsByID :many
SELECT id, key, description FROM rbac.permissions WHERE id = ANY(@ids::uuid[]) ORDER BY key;

-- name: GrantPermissions :exec
INSERT INTO rbac.role_permissions (role_id, permission_id)
SELECT @role_id, unnest(@permission_ids::uuid[])
ON CONFLICT DO NOTHING;

-- name: RevokePermissions :exec
DELETE FROM rbac.role_permissions WHERE role_id = @role_id AND permission_id = ANY(@permission_ids::uuid[]);

-- name: UpdateRole :one
UPDATE rbac.roles SET name = @name, description = @description
WHERE id = @id AND organization_id = @organization_id
RETURNING id, organization_id, name, description, is_system, created_at;

-- RoleUse counts who would lose the role with it: the people holding it, the
-- groups holding it, and the invitations to it that can still be accepted or
-- resent.
-- name: RoleUse :one
SELECT
    (SELECT count(*) FROM rbac.user_roles ur WHERE ur.role_id = @role_id AND ur.organization_id = @organization_id) AS people,
    (SELECT count(*) FROM rbac.group_roles gr WHERE gr.role_id = @role_id AND gr.organization_id = @organization_id) AS groups,
    (SELECT count(*) FROM organization.invites i WHERE i.role_id = @role_id AND i.organization_id = @organization_id AND i.status IN ('pending', 'expired')) AS invitations;

-- name: DeleteRole :exec
DELETE FROM rbac.roles WHERE id = @id AND organization_id = @organization_id;

-- name: GrantPermission :exec
INSERT INTO rbac.role_permissions (role_id, permission_id)
VALUES (@role_id, @permission_id)
ON CONFLICT DO NOTHING;

-- name: RevokePermission :exec
DELETE FROM rbac.role_permissions WHERE role_id = @role_id AND permission_id = @permission_id;

-- AssignUserRole grants a role to a user only when the role belongs to the
-- organization and the user is a live member of it, checked in the same statement as
-- the write. A user_roles row is what makes someone a member, so without the
-- membership check one insert could pull a user from another organization in.
-- Membership is a user_roles row in the organization whose role is the organization's own
-- (as CheckOrganizationMembership reads it), or the organization being the account's home:
-- an admin-created account has no membership row until its first role, and
-- that first assignment must still work. valid is false for a missing,
-- deleted or foreign user and for a missing or foreign role alike, and true
-- for a role the user already holds (the insert is then a no-op). Giving a
-- role someone holds for a time through an access request gives it for good:
-- the request's end is cleared, so its sweep leaves the role.
-- name: AssignUserRole :one
WITH allowed AS (
    SELECT (
        EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = @role_id AND ro.organization_id = @organization_id)
        AND EXISTS (
            SELECT 1 FROM account.users account
            WHERE account.id = @user_id AND account.deleted_at IS NULL
              AND (
                  account.organization_id = @organization_id
                  OR EXISTS (
                      SELECT 1 FROM rbac.user_roles membership
                      JOIN rbac.roles member_role
                        ON member_role.id = membership.role_id AND member_role.organization_id = membership.organization_id
                      WHERE membership.user_id = @user_id AND membership.organization_id = @organization_id
                  )
              )
        )
    ) AS ok
),
ins AS (
    INSERT INTO rbac.user_roles (user_id, organization_id, role_id, granted_by)
    SELECT @user_id, @organization_id, @role_id, @granted_by
    FROM allowed
    WHERE allowed.ok
    ON CONFLICT DO NOTHING
),
for_good AS (
    UPDATE rbac.access_requests SET access_ends_at = NULL
    WHERE organization_id = @organization_id AND requester_id = @user_id AND role_id = @role_id
      AND status = 'approved' AND granted AND ended_at IS NULL AND access_ends_at IS NOT NULL
      AND (SELECT ok FROM allowed)
)
SELECT allowed.ok AS valid FROM allowed;

-- UnassignUserRole deletes only within the given organization, and deliberately does
-- not require the role to be the organization's own: a row attaching another
-- organization's role must stay removable by the organization it was written into.
-- name: UnassignUserRole :exec
DELETE FROM rbac.user_roles WHERE user_id = @user_id AND organization_id = @organization_id AND role_id = @role_id;

-- LeftOrganization reports whether the user is no longer a member of the organization: it
-- isn't their home and they hold no role there.
-- name: LeftOrganization :one
SELECT (NOT EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = @user_id::uuid AND ur.organization_id = @organization_id::uuid)
    AND NOT EXISTS (SELECT 1 FROM account.users u WHERE u.id = @user_id::uuid AND u.organization_id = @organization_id::uuid))::bool
    AS left_organization;

-- name: CheckPermission :one
SELECT EXISTS (
    SELECT 1
    FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id AND p.key = @perm_key
    UNION ALL
    SELECT 1
    FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.user_id = @user_id AND gm.organization_id = @organization_id AND p.key = @perm_key
) AS allowed;

-- name: ListEffectivePermissions :many
SELECT p.key
FROM rbac.user_roles ur
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id
UNION
SELECT p.key
FROM organization.group_members gm
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE gm.user_id = @user_id AND gm.organization_id = @organization_id
ORDER BY key;

-- name: RemoveRoleFromGroup :exec
DELETE FROM rbac.group_roles WHERE group_id = @group_id AND organization_id = @organization_id AND role_id = @role_id;

-- name: ListGroupRoles :many
SELECT gr.role_id, ro.name, gr.granted_at
FROM rbac.group_roles gr
JOIN rbac.roles ro ON ro.id = gr.role_id
WHERE gr.group_id = @group_id AND gr.organization_id = @organization_id
ORDER BY ro.name;

-- name: AssignRoleToGroup :one
WITH ins AS (
    INSERT INTO rbac.group_roles (organization_id, group_id, role_id, granted_by)
    SELECT @organization_id, @group_id, @role_id, @granted_by
    WHERE EXISTS (SELECT 1 FROM organization.groups g WHERE g.id = @group_id AND g.organization_id = @organization_id)
      AND EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = @role_id AND ro.organization_id = @organization_id)
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT (
    EXISTS (SELECT 1 FROM ins)
    OR EXISTS (SELECT 1 FROM rbac.group_roles existing WHERE existing.group_id = @group_id AND existing.role_id = @role_id AND existing.organization_id = @organization_id)
) AS valid;

-- name: ExplainGrants :many
SELECT 'direct'::text AS via, NULL::uuid AS group_id, NULL::text AS group_name, ro.id AS role_id, ro.name AS role_name
FROM rbac.user_roles ur
JOIN rbac.roles ro ON ro.id = ur.role_id
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id AND p.key = @perm_key
UNION ALL
SELECT 'group'::text AS via, g.id AS group_id, g.name AS group_name, ro.id AS role_id, ro.name AS role_name
FROM organization.group_members gm
JOIN organization.groups g ON g.id = gm.group_id AND g.organization_id = gm.organization_id
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
JOIN rbac.roles ro ON ro.id = gr.role_id
JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE gm.user_id = @user_id AND gm.organization_id = @organization_id AND p.key = @perm_key
ORDER BY via, group_name NULLS FIRST;

-- name: ExplainAllGrants :many
-- Every grant behind a person's permissions in the organization: each permission
-- with the role granting it, held directly or through which group.
SELECT p.key AS permission, 'direct'::text AS via, NULL::uuid AS group_id, NULL::text AS group_name, ro.id AS role_id, ro.name AS role_name
FROM rbac.user_roles ur
JOIN rbac.roles ro ON ro.id = ur.role_id
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id
UNION ALL
SELECT p.key AS permission, 'group'::text AS via, g.id AS group_id, g.name AS group_name, ro.id AS role_id, ro.name AS role_name
FROM organization.group_members gm
JOIN organization.groups g ON g.id = gm.group_id AND g.organization_id = gm.organization_id
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
JOIN rbac.roles ro ON ro.id = gr.role_id
JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE gm.user_id = @user_id AND gm.organization_id = @organization_id
ORDER BY permission, via, group_name NULLS FIRST, role_name;

-- name: RoleHolderCounts :many
-- Per role of the organization: the live people holding it directly, those holding
-- it only through a group, and the groups granted it.
SELECT ro.id AS role_id,
       (SELECT count(DISTINCT ur.user_id) FROM rbac.user_roles ur
          JOIN account.users u ON u.id = ur.user_id AND u.deleted_at IS NULL
         WHERE ur.organization_id = ro.organization_id AND ur.role_id = ro.id)::int AS people_direct,
       (SELECT count(DISTINCT gm.user_id) FROM rbac.group_roles gr
          JOIN organization.group_members gm ON gm.group_id = gr.group_id AND gm.organization_id = gr.organization_id
          JOIN account.users u ON u.id = gm.user_id AND u.deleted_at IS NULL
         WHERE gr.organization_id = ro.organization_id AND gr.role_id = ro.id
           AND NOT EXISTS (SELECT 1 FROM rbac.user_roles ur
                            WHERE ur.user_id = gm.user_id AND ur.organization_id = ro.organization_id AND ur.role_id = ro.id))::int AS people_through_groups,
       (SELECT count(*) FROM rbac.group_roles gr WHERE gr.organization_id = ro.organization_id AND gr.role_id = ro.id)::int AS groups
FROM rbac.roles ro
WHERE ro.organization_id = @organization_id;

-- name: ListRoleHolderPeople :many
-- One page of the live people holding a role of the organization, by email: whether
-- directly, and the groups they hold it through.
SELECT u.id, u.email, COALESCE(u.display_name, '')::text AS display_name,
       EXISTS (SELECT 1 FROM rbac.user_roles ur
                WHERE ur.user_id = u.id AND ur.organization_id = @organization_id AND ur.role_id = @role_id) AS direct,
       COALESCE((SELECT array_agg(gr.group_id ORDER BY gr.group_id) FROM rbac.group_roles gr
                   JOIN organization.group_members gm ON gm.group_id = gr.group_id AND gm.organization_id = gr.organization_id
                  WHERE gr.organization_id = @organization_id AND gr.role_id = @role_id AND gm.user_id = u.id), '{}')::uuid[] AS via_groups
FROM account.users u
WHERE u.deleted_at IS NULL
  AND (EXISTS (SELECT 1 FROM rbac.user_roles ur
                WHERE ur.user_id = u.id AND ur.organization_id = @organization_id AND ur.role_id = @role_id)
       OR EXISTS (SELECT 1 FROM rbac.group_roles gr
                    JOIN organization.group_members gm ON gm.group_id = gr.group_id AND gm.organization_id = gr.organization_id
                   WHERE gr.organization_id = @organization_id AND gr.role_id = @role_id AND gm.user_id = u.id))
ORDER BY u.email, u.id
LIMIT @row_limit OFFSET @row_offset;

-- name: ListRoleHolderGroups :many
-- The groups of the organization granted a role, by name.
SELECT g.id, g.name
FROM rbac.group_roles gr
JOIN organization.groups g ON g.id = gr.group_id AND g.organization_id = gr.organization_id
WHERE gr.organization_id = @organization_id AND gr.role_id = @role_id
ORDER BY g.name, g.id;

-- UsersWithPermission lists the active members of the organization who hold the
-- permission, directly or through a group: the people to tell about something
-- only they can act on, such as an access request.
-- name: UsersWithPermission :many
SELECT DISTINCT holder.user_id
FROM (
    SELECT ur.user_id
    FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.organization_id = @organization_id AND p.key = @perm_key
    UNION
    SELECT gm.user_id
    FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.organization_id = @organization_id AND p.key = @perm_key
) holder
JOIN account.users u ON u.id = holder.user_id AND u.deleted_at IS NULL AND u.status = 'active'
LIMIT 200;
