-- 0061_agents — first-class non-human principals (AI agents / MCP clients); auth by secret → short-lived scoped token (actor_type="agent").
-- Ephemeral by design (re-mint, not refresh); distinct from users and long-lived service principals so downstream can identify agents.
CREATE TABLE auth.agents (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    secret_hash       TEXT NOT NULL,
    scopes            TEXT[] NOT NULL DEFAULT '{}',
    token_ttl_seconds INTEGER NOT NULL DEFAULT 600,   -- ephemeral; clamped 60..3600
    disabled_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_tenant ON auth.agents (tenant_id);
