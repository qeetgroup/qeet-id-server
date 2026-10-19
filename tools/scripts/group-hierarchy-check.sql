-- group-hierarchy-check.sql — lists groups whose nesting is broken. Read-only.
--
--   foreign_parent  the parent is a group of another organization. Migration
--                   0136 detaches these (they become top-level).
--   loop            the group is its own ancestor (a parent chain that comes
--                   back to it, including a group that is its own parent).
--                   Nothing repairs these automatically.
--
-- Run it once against each database before deploying migration 0136, and record
-- the result on the issue:
--   psql "$DATABASE_URL" -f tools/scripts/group-hierarchy-check.sql
WITH RECURSIVE walk (start_id, current_id, path) AS (
    SELECT g.id, g.parent_id, ARRAY[g.id]
    FROM tenant.groups g
    WHERE g.parent_id IS NOT NULL
    UNION ALL
    SELECT w.start_id, g.parent_id, w.path || g.id
    FROM walk w
    JOIN tenant.groups g ON g.id = w.current_id
    WHERE g.parent_id IS NOT NULL AND g.id <> ALL (w.path)
)
SELECT 'foreign_parent' AS problem, child.tenant_id, child.id, child.name, child.parent_id
FROM tenant.groups child
JOIN tenant.groups parent ON parent.id = child.parent_id
WHERE parent.tenant_id <> child.tenant_id
UNION ALL
SELECT 'loop' AS problem, g.tenant_id, g.id, g.name, g.parent_id
FROM tenant.groups g
WHERE g.id IN (SELECT start_id FROM walk WHERE current_id = start_id)
ORDER BY problem, tenant_id, name;
