-- 0206_tenant_purges — the record that an organisation's data was purged.
--
-- A deleted organisation's data is purged once its restore window has
-- passed. This record outlives the data: which organisation, when it was
-- deleted and purged, and how many rows each table lost, as evidence the
-- deletion was carried out. It names the organisation by id and slug only.
CREATE TABLE platform.tenant_purges (
    tenant_id   UUID PRIMARY KEY,
    slug        TEXT NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL,
    purged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rows_purged JSONB NOT NULL DEFAULT '{}',
    accounts_removed  INTEGER NOT NULL DEFAULT 0,
    accounts_detached INTEGER NOT NULL DEFAULT 0
);
