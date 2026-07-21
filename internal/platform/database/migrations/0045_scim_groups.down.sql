DROP INDEX IF EXISTS tenant.uq_groups_tenant_external;

ALTER TABLE tenant.groups
    DROP COLUMN IF EXISTS external_id,
    DROP COLUMN IF EXISTS updated_at;
