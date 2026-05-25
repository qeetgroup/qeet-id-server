CREATE TABLE tenant.branding (
    tenant_id           UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    logo_url            TEXT,
    primary_color       TEXT,
    secondary_color     TEXT,
    custom_domain       TEXT,
    email_from_name     TEXT,
    email_from_address  TEXT,
    settings            JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
