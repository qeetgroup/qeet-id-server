-- Queries for the groups domain.
-- All queries are static; audit.Record and outbox.Enqueue cross-context calls
-- stay hand-written on the same pgx.Tx.

-- name: InsertGroup :one
INSERT INTO tenant.groups (tenant_id, parent_id, name, description)
VALUES ($1, $2, $3, $4)
RETURNING id, tenant_id, parent_id, name, description, created_at;

-- name: ListGroups :many
SELECT id, tenant_id, parent_id, name, description, created_at
FROM tenant.groups WHERE tenant_id = $1 ORDER BY name;

-- name: DeleteGroup :one
DELETE FROM tenant.groups WHERE id = $1 AND tenant_id = $2 RETURNING name;

-- name: UpdateGroup :one
UPDATE tenant.groups
SET name = $1, description = $2, parent_id = $3
WHERE id = $4 AND tenant_id = $5
RETURNING id, tenant_id, parent_id, name, description, created_at;

-- name: GroupExists :one
SELECT EXISTS(SELECT 1 FROM tenant.groups WHERE id = $1 AND tenant_id = $2);

-- name: InsertGroupMember :exec
INSERT INTO tenant.group_members (group_id, user_id, tenant_id)
VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;

-- name: DeleteGroupMember :exec
DELETE FROM tenant.group_members
WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3;

-- name: ListGroupMembers :many
SELECT gm.user_id, u.email, u.display_name
FROM tenant.group_members gm
JOIN "user".users u ON u.id = gm.user_id
WHERE gm.group_id = $1 AND gm.tenant_id = $2 AND u.deleted_at IS NULL
ORDER BY u.email;
