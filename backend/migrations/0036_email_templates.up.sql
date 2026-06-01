-- Per-tenant overrides for transactional email templates. The catalog of
-- template keys and their default subject/body lives in code; this table only
-- stores a tenant's customisations, so a missing row means "use the default".

CREATE TABLE tenant.email_templates (
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    template_key TEXT NOT NULL,
    subject      TEXT NOT NULL,
    body         TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, template_key)
);
