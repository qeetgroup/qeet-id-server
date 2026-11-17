-- Queries for the groups domain.
-- All queries are static; audit.Record and outbox.Enqueue cross-context calls
-- stay hand-written on the same pgx.Tx.

-- name: InsertGroup :one
INSERT INTO organization.groups (organization_id, parent_id, name, description)
VALUES ($1, $2, $3, $4)
RETURNING id, organization_id, parent_id, name, description, created_at;

-- name: DeleteGroup :one
DELETE FROM organization.groups WHERE id = $1 AND organization_id = $2 RETURNING name;

-- UpdateGroup changes only what the caller sent: a NULL name or description
-- keeps the current one, and the parent changes only when set_parent is true
-- (a NULL parent_id then makes the group top-level).
-- name: UpdateGroup :one
UPDATE organization.groups
SET name        = COALESCE(sqlc.narg('name'), name),
    description = COALESCE(sqlc.narg('description'), description),
    parent_id   = CASE WHEN sqlc.arg('set_parent')::boolean THEN sqlc.narg('parent_id')::uuid ELSE parent_id END
WHERE id = sqlc.arg('id') AND organization_id = sqlc.arg('organization_id')
RETURNING id, organization_id, parent_id, name, description, created_at;

-- IsGroupOrDescendant reports whether candidate is the group itself or one of
-- its subgroups, at any depth: making it the group's parent would loop. UNION
-- (not UNION ALL) keeps the walk finite even over a loop already in the data.
-- name: IsGroupOrDescendant :one
WITH RECURSIVE subtree (id) AS (
    SELECT g.id FROM organization.groups g
    WHERE g.id = sqlc.arg('group_id') AND g.organization_id = sqlc.arg('organization_id')
    UNION
    SELECT child.id FROM organization.groups child
    JOIN subtree AS above ON child.parent_id = above.id
    WHERE child.organization_id = sqlc.arg('organization_id')
)
SELECT (count(*) > 0)::boolean AS is_descendant FROM subtree WHERE subtree.id = sqlc.arg('candidate_id')::uuid;

-- name: GroupExists :one
SELECT EXISTS(SELECT 1 FROM organization.groups WHERE id = $1 AND organization_id = $2);

-- InsertGroupMember adds a user to a group only when the user is a live member
-- of the organization, checked in the same statement as the write; the caller has
-- already checked that the group is the organization's. Membership is the rule role
-- assignment uses: a user_roles row in the organization whose role is the organization's
-- own, or the organization being the account's home (an admin-created account has no
-- membership row until its first role). valid is false for a missing, deleted
-- or foreign user alike, and true for someone already in the group. Adding
-- someone a single sign-on put in the group makes the membership the
-- administrator's, so their sign-ins no longer remove it.
-- name: InsertGroupMember :one
WITH allowed AS (
    SELECT EXISTS (
        SELECT 1 FROM account.users account
        WHERE account.id = @user_id AND account.deleted_at IS NULL
          AND (
              account.organization_id = @organization_id::uuid
              OR EXISTS (
                  SELECT 1 FROM rbac.user_roles membership
                  JOIN rbac.roles member_role
                    ON member_role.id = membership.role_id AND member_role.organization_id = membership.organization_id
                  WHERE membership.user_id = @user_id AND membership.organization_id = @organization_id
              )
          )
    ) AS ok
),
ins AS (
    INSERT INTO organization.group_members AS gm (group_id, user_id, organization_id)
    SELECT @group_id, @user_id, @organization_id
    FROM allowed
    WHERE allowed.ok
    ON CONFLICT (group_id, user_id) DO UPDATE SET source_connection_id = NULL
    WHERE gm.organization_id = EXCLUDED.organization_id AND gm.source_connection_id IS NOT NULL
)
SELECT allowed.ok AS valid FROM allowed;

-- name: DeleteGroupMember :execrows
DELETE FROM organization.group_members
WHERE group_id = $1 AND user_id = $2 AND organization_id = $3;

-- ListGroupMembers lists only people who are members of the group's organization, by
-- the same rule as InsertGroupMember, so a row written for someone outside it
-- never shows their email or name.
-- name: ListGroupMembers :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT gm.user_id, u.email, u.display_name
FROM organization.group_members gm
JOIN account.users u ON u.id = gm.user_id
WHERE gm.group_id = $1 AND gm.organization_id = $2 AND u.deleted_at IS NULL
  AND (
      u.organization_id = gm.organization_id
      OR EXISTS (
          SELECT 1 FROM rbac.user_roles membership
          JOIN rbac.roles member_role
            ON member_role.id = membership.role_id AND member_role.organization_id = membership.organization_id
          WHERE membership.user_id = gm.user_id AND membership.organization_id = gm.organization_id
      )
  )
ORDER BY u.email
LIMIT 1001;
