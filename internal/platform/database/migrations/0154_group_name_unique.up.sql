-- 0154_group_name_unique — a group's name is unique in its organization,
-- ignoring case and surrounding space.
--
-- Nothing constrained tenant.groups.name, so the console, bulk import and
-- templates, which all tell groups apart by name, could create two groups an
-- administrator can't tell apart. Groups an identity provider provisions over
-- SCIM with an externalId are exempt: they are matched by that id, and a
-- provider may hold two groups of one name.
--
-- Names that already collide would stop the index being built, so every group
-- after the first of a colliding name, oldest first, gets the start of its id
-- appended: "Engineering" becomes "Engineering (1a2b3c4d)". Nothing is deleted.
UPDATE tenant.groups g
SET name = BTRIM(g.name) || ' (' || LEFT(g.id::text, 8) || ')', updated_at = NOW()
FROM (
    SELECT id, ROW_NUMBER() OVER (PARTITION BY tenant_id, LOWER(BTRIM(name)) ORDER BY created_at, id) AS n
    FROM tenant.groups
    WHERE external_id IS NULL
) ranked
WHERE ranked.id = g.id AND ranked.n > 1;

CREATE UNIQUE INDEX uq_groups_tenant_name ON tenant.groups (tenant_id, LOWER(BTRIM(name))) WHERE external_id IS NULL;
