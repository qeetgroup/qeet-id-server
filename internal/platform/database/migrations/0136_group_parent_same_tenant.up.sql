-- 0136_group_parent_same_tenant — a group's parent must be a group of the same
-- organization.
--
-- tenant.groups.parent_id referenced groups(id) only, so a group could be nested
-- under another organization's group, and deleting that group cascaded into this
-- one's subgroups. A group whose parent is in another organization is detached
-- first: it becomes top-level and nothing is deleted. Then the key is replaced by
-- one on (tenant_id, parent_id), which needs (tenant_id, id) to be unique. A NULL
-- parent_id is not checked, so top-level groups are unaffected, and deleting a
-- group still deletes its subgroups. tools/scripts/group-hierarchy-check.sql lists
-- the rows this detaches, and any loops, before it runs.
UPDATE tenant.groups child
SET parent_id = NULL
FROM tenant.groups parent
WHERE child.parent_id = parent.id AND parent.tenant_id <> child.tenant_id;

ALTER TABLE tenant.groups ADD CONSTRAINT groups_tenant_id_id_key UNIQUE (tenant_id, id);

ALTER TABLE tenant.groups DROP CONSTRAINT groups_parent_id_fkey;

ALTER TABLE tenant.groups
    ADD CONSTRAINT groups_tenant_parent_fkey
    FOREIGN KEY (tenant_id, parent_id) REFERENCES tenant.groups (tenant_id, id) ON DELETE CASCADE;
