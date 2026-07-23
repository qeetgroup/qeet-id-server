-- 0036_email_templates — per-tenant overrides for transactional emails (catalog + defaults live in code; missing row = use the default)

CREATE TABLE tenant.email_templates (
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    template_key TEXT NOT NULL,
    subject      TEXT NOT NULL,
    body         TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, template_key)
);
