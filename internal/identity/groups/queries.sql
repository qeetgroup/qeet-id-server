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

-- UpdateGroup changes only what the caller sent: a NULL name or description
-- keeps the current one, and the parent changes only when set_parent is true
-- (a NULL parent_id then makes the group top-level).
-- name: UpdateGroup :one
UPDATE tenant.groups
SET name        = COALESCE(sqlc.narg('name'), name),
    description = COALESCE(sqlc.narg('description'), description),
    parent_id   = CASE WHEN sqlc.arg('set_parent')::boolean THEN sqlc.narg('parent_id')::uuid ELSE parent_id END
WHERE id = sqlc.arg('id') AND tenant_id = sqlc.arg('tenant_id')
RETURNING id, tenant_id, parent_id, name, description, created_at;

-- IsGroupOrDescendant reports whether candidate is the group itself or one of
-- its subgroups, at any depth: making it the group's parent would loop. UNION
-- (not UNION ALL) keeps the walk finite even over a loop already in the data.
-- name: IsGroupOrDescendant :one
WITH RECURSIVE subtree (id) AS (
    SELECT g.id FROM tenant.groups g
    WHERE g.id = sqlc.arg('group_id') AND g.tenant_id = sqlc.arg('tenant_id')
    UNION
    SELECT child.id FROM tenant.groups child
    JOIN subtree AS above ON child.parent_id = above.id
    WHERE child.tenant_id = sqlc.arg('tenant_id')
)
SELECT (count(*) > 0)::boolean AS is_descendant FROM subtree WHERE subtree.id = sqlc.arg('candidate_id')::uuid;

-- name: GroupExists :one
SELECT EXISTS(SELECT 1 FROM tenant.groups WHERE id = $1 AND tenant_id = $2);

-- InsertGroupMember adds a user to a group only when the user is a live member
-- of the tenant, checked in the same statement as the write; the caller has
-- already checked that the group is the tenant's. Membership is the rule role
-- assignment uses: a user_roles row in the tenant whose role is the tenant's
-- own, or the tenant being the account's home (an admin-created account has no
-- membership row until its first role). valid is false for a missing, deleted
-- or foreign user alike, and true for someone already in the group.
-- name: InsertGroupMember :one
WITH allowed AS (
    SELECT EXISTS (
        SELECT 1 FROM "user".users account
        WHERE account.id = @user_id AND account.deleted_at IS NULL
          AND (
              account.tenant_id = @tenant_id::uuid
              OR EXISTS (
                  SELECT 1 FROM rbac.user_roles membership
                  JOIN rbac.roles member_role
                    ON member_role.id = membership.role_id AND member_role.tenant_id = membership.tenant_id
                  WHERE membership.user_id = @user_id AND membership.tenant_id = @tenant_id
              )
          )
    ) AS ok
),
ins AS (
    INSERT INTO tenant.group_members (group_id, user_id, tenant_id)
    SELECT @group_id, @user_id, @tenant_id
    FROM allowed
    WHERE allowed.ok
    ON CONFLICT DO NOTHING
)
SELECT allowed.ok AS valid FROM allowed;

-- name: DeleteGroupMember :execrows
DELETE FROM tenant.group_members
WHERE group_id = $1 AND user_id = $2 AND tenant_id = $3;

-- ListGroupMembers lists only people who are members of the group's tenant, by
-- the same rule as InsertGroupMember, so a row written for someone outside it
-- never shows their email or name.
-- name: ListGroupMembers :many
SELECT gm.user_id, u.email, u.display_name
FROM tenant.group_members gm
JOIN "user".users u ON u.id = gm.user_id
WHERE gm.group_id = $1 AND gm.tenant_id = $2 AND u.deleted_at IS NULL
  AND (
      u.tenant_id = gm.tenant_id
      OR EXISTS (
          SELECT 1 FROM rbac.user_roles membership
          JOIN rbac.roles member_role
            ON member_role.id = membership.role_id AND member_role.tenant_id = membership.tenant_id
          WHERE membership.user_id = gm.user_id AND membership.tenant_id = gm.tenant_id
      )
  )
ORDER BY u.email;
