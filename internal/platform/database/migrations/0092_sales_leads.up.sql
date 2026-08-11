-- 0092_sales_leads — in-app "Contact sales" leads (Enterprise CTA).
-- Platform-level (not tenant-scoped): a lead can be submitted before any org
-- exists (during onboarding) or from an existing org's billing page. tenant_id
-- / user_id are captured when known, both optional.
CREATE TABLE platform.sales_leads (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID REFERENCES tenant.tenants(id) ON DELETE SET NULL,
    user_id     UUID,
    name        TEXT NOT NULL DEFAULT '',
    email       TEXT NOT NULL,
    company     TEXT NOT NULL DEFAULT '',
    team_size   TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'new',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sales_leads_created ON platform.sales_leads (created_at DESC);
