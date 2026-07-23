-- 0037_retention — per-tenant retention policy (soft-deleted users); opt-in, disabled by default so no auto-deletion happens unasked

CREATE TABLE tenant.retention_policy (
    tenant_id             UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    deleted_users_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_users_days    INT     NOT NULL DEFAULT 30 CHECK (deleted_users_days BETWEEN 1 AND 3650),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
