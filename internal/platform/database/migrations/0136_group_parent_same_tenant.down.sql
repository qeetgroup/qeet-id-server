-- Restores the id-only parent key; parents detached by the up migration are not restored.
ALTER TABLE tenant.groups DROP CONSTRAINT IF EXISTS groups_tenant_parent_fkey;

ALTER TABLE tenant.groups
    ADD CONSTRAINT groups_parent_id_fkey
    FOREIGN KEY (parent_id) REFERENCES tenant.groups (id) ON DELETE CASCADE;

ALTER TABLE tenant.groups DROP CONSTRAINT IF EXISTS groups_tenant_id_id_key;
