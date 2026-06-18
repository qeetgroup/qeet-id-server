-- AI-agent identities: first-class, non-human principals for AI agents / MCP
-- clients. An agent authenticates with its secret and receives a SHORT-LIVED,
-- scoped access token marked actor_type="agent" (ephemeral by design — agents
-- re-mint rather than refresh). Distinct from human users and from long-lived
-- service principals, so downstream (incl. MCP servers) can identify agents.
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
