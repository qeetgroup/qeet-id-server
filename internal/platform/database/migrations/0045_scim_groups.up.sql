-- 0045_scim_groups — SCIM Groups on the existing tenant.groups (0021): adds external_id
-- (the IdP's group key, for reconcile/round-trip) and updated_at (SCIM meta.lastModified).

ALTER TABLE tenant.groups
    ADD COLUMN IF NOT EXISTS external_id TEXT,
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- external_id is unique per tenant when set; NULLs allowed for interactively-created groups.
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_external
    ON tenant.groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL;
