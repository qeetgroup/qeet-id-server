-- Per-tenant IP allow/deny rules (CIDR). Deny rules win over allow rules; if
-- any allow rule exists, an address must match one to pass. Enforcement is
-- gated by an explicit per-tenant flag to avoid accidental lockout.

CREATE TABLE tenant.ip_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    cidr       TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL DEFAULT 'allow' CHECK (action IN ('allow', 'deny')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ip_rules_tenant ON tenant.ip_rules (tenant_id);

CREATE TABLE tenant.ip_rules_config (
    tenant_id  UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    enabled    BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
