-- Queries for the identitylink domain, compiled by sqlc into ./dbgen.

-- name: HomeIn :one
SELECT EXISTS (
    SELECT 1 FROM account.users WHERE id = @user_id AND organization_id = @organization_id AND deleted_at IS NULL
);

-- name: AddressVerified :one
-- Proved by the account, or vouched for by its organization's directory.
SELECT (email_verified_at IS NOT NULL OR provisioned_via IS NOT DISTINCT FROM 'scim')::bool
FROM account.users WHERE id = @user_id;

-- name: MarkAddressVerified :exec
UPDATE account.users SET email_verified_at = NOW(), updated_at = NOW()
WHERE id = @user_id AND email_verified_at IS NULL;

-- name: Administers :one
-- Whether the account owns the organization or holds a permission outside
-- member_permissions there, directly or through a group.
SELECT EXISTS (
    SELECT 1 FROM rbac.user_roles ur
    JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id
    LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
    LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id
      AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[]))))
    UNION ALL
    SELECT 1 FROM organization.group_members gm
    JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
    JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
    LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
    LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
    WHERE gm.user_id = @user_id AND gm.organization_id = @organization_id
      AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[]))))
);

-- name: LinkedAdministrators :one
-- The administrators (as Administers) linked to the organization's connection
-- connection_id or, when that is the nil UUID, to its social provider.
SELECT coalesce(array_agg(DISTINCT e.user_id), '{}')::uuid[] FROM account.external_identities e
WHERE e.organization_id = @organization_id
  AND (e.connection_id = @connection_id::uuid
       OR (@connection_id::uuid = '00000000-0000-0000-0000-000000000000'::uuid AND e.connection_id IS NULL AND e.provider = @provider::text))
  AND (EXISTS (
        SELECT 1 FROM rbac.user_roles ur
        JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id
        LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
        LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = e.user_id AND ur.organization_id = @organization_id
          AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[])))))
    OR EXISTS (
        SELECT 1 FROM organization.group_members gm
        JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
        JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
        LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
        LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
        WHERE gm.user_id = e.user_id AND gm.organization_id = @organization_id
          AND ((ro.is_system AND ro.name = 'owner') OR (p.key IS NOT NULL AND NOT (p.key = ANY(@member_permissions::text[]))))));
