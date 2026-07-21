-- SCIM 2.0 Groups support. Groups map onto the existing tenant.groups /
-- tenant.group_members tables (migration 0021). SCIM needs two things the
-- org/team model didn't carry:
--   - external_id: the IdP's own key for the group, so Okta/Entra can
--     reconcile on it and we can round-trip it back in the SCIM resource.
--   - updated_at: SCIM meta.lastModified; the table only had created_at.

ALTER TABLE tenant.groups
    ADD COLUMN IF NOT EXISTS external_id TEXT,
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- external_id is unique per tenant when set (an IdP won't reuse one), but
-- NULLs are allowed for the many interactively-created groups.
CREATE UNIQUE INDEX IF NOT EXISTS uq_groups_tenant_external
    ON tenant.groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL;
