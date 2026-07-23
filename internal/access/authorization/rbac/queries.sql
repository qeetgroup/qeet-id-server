-- Queries for the rbac domain. All queries are sqlc-generated, including the two
-- awkward ones: AssignRoleToGroup (a conditional CTE INSERT whose RETURNING is
-- folded into an EXISTS check, returning a single bool) and ExplainGrants (a
-- two-armed UNION ALL with typed NULL columns for the direct arm).

-- name: UpsertPermission :one
INSERT INTO rbac.permissions (key, description)
VALUES (@key, @description)
ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description
RETURNING id, key, description;

-- name: ListPermissions :many
SELECT id, key, description FROM rbac.permissions ORDER BY key;

-- name: CreateRole :one
INSERT INTO rbac.roles (tenant_id, name, description, is_system)
VALUES (@tenant_id, @name, @description, @is_system)
RETURNING id, tenant_id, name, description, is_system, created_at;

-- name: ListRoles :many
SELECT id, tenant_id, name, description, is_system, created_at
FROM rbac.roles
WHERE tenant_id = @tenant_id
ORDER BY name;

-- name: GetRoleTenant :one
SELECT tenant_id FROM rbac.roles WHERE id = @id;

-- name: ListRolePermissions :many
SELECT p.id, p.key, p.description
FROM rbac.permissions p
JOIN rbac.role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = @role_id
ORDER BY p.key;

-- name: GrantPermission :exec
INSERT INTO rbac.role_permissions (role_id, permission_id)
VALUES (@role_id, @permission_id)
ON CONFLICT DO NOTHING;

-- name: RevokePermission :exec
DELETE FROM rbac.role_permissions WHERE role_id = @role_id AND permission_id = @permission_id;

-- name: AssignUserRole :exec
INSERT INTO rbac.user_roles (user_id, tenant_id, role_id, granted_by)
VALUES (@user_id, @tenant_id, @role_id, @granted_by)
ON CONFLICT DO NOTHING;

-- name: UnassignUserRole :exec
DELETE FROM rbac.user_roles WHERE user_id = @user_id AND tenant_id = @tenant_id AND role_id = @role_id;

-- name: CheckPermission :one
SELECT EXISTS (
    SELECT 1
    FROM rbac.user_roles ur
    JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id AND p.key = @perm_key
    UNION ALL
    SELECT 1
    FROM tenant.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
    JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
    JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.user_id = @user_id AND gm.tenant_id = @tenant_id AND p.key = @perm_key
) AS allowed;

-- name: ListEffectivePermissions :many
SELECT p.key
FROM rbac.user_roles ur
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id
UNION
SELECT p.key
FROM tenant.group_members gm
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE gm.user_id = @user_id AND gm.tenant_id = @tenant_id
ORDER BY key;

-- name: RemoveRoleFromGroup :exec
DELETE FROM rbac.group_roles WHERE group_id = @group_id AND tenant_id = @tenant_id AND role_id = @role_id;

-- name: ListGroupRoles :many
SELECT gr.role_id, ro.name, gr.granted_at
FROM rbac.group_roles gr
JOIN rbac.roles ro ON ro.id = gr.role_id
WHERE gr.group_id = @group_id AND gr.tenant_id = @tenant_id
ORDER BY ro.name;

-- name: AssignRoleToGroup :one
WITH ins AS (
    INSERT INTO rbac.group_roles (tenant_id, group_id, role_id, granted_by)
    SELECT @tenant_id, @group_id, @role_id, @granted_by
    WHERE EXISTS (SELECT 1 FROM tenant.groups g WHERE g.id = @group_id AND g.tenant_id = @tenant_id)
      AND EXISTS (SELECT 1 FROM rbac.roles ro WHERE ro.id = @role_id AND ro.tenant_id = @tenant_id)
    ON CONFLICT DO NOTHING
    RETURNING 1
)
SELECT (
    EXISTS (SELECT 1 FROM ins)
    OR EXISTS (SELECT 1 FROM rbac.group_roles existing WHERE existing.group_id = @group_id AND existing.role_id = @role_id AND existing.tenant_id = @tenant_id)
) AS valid;

-- name: ExplainGrants :many
SELECT 'direct'::text AS via, NULL::uuid AS group_id, NULL::text AS group_name, ro.id AS role_id, ro.name AS role_name
FROM rbac.user_roles ur
JOIN rbac.roles ro ON ro.id = ur.role_id
JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id AND p.key = @perm_key
UNION ALL
SELECT 'group'::text AS via, g.id AS group_id, g.name AS group_name, ro.id AS role_id, ro.name AS role_name
FROM tenant.group_members gm
JOIN tenant.groups g ON g.id = gm.group_id AND g.tenant_id = gm.tenant_id
JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
JOIN rbac.roles ro ON ro.id = gr.role_id
JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
JOIN rbac.permissions p ON p.id = rp.permission_id
WHERE gm.user_id = @user_id AND gm.tenant_id = @tenant_id AND p.key = @perm_key
ORDER BY via, group_name NULLS FIRST;
