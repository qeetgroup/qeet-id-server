-- Per-tenant data-retention policy. Today it governs how long soft-deleted
-- users are kept before being permanently purged. Disabled by default so a
-- tenant must opt in before any automatic deletion happens.

CREATE TABLE tenant.retention_policy (
    tenant_id             UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    deleted_users_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_users_days    INT     NOT NULL DEFAULT 30 CHECK (deleted_users_days BETWEEN 1 AND 3650),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
