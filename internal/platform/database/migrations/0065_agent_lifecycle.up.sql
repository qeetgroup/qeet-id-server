-- 0065_agent_lifecycle — agent status tri-state (active → suspended → decommissioned) replacing the boolean disabled_at.
-- Suspend is reversible, decommission is terminal; disabled_at is kept in sync for anything still reading it.
ALTER TABLE auth.agents
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'decommissioned'));

-- Backfill: previously-disabled agents map to 'suspended' (reversible).
UPDATE auth.agents SET status = 'suspended' WHERE disabled_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_tenant_status ON auth.agents (tenant_id, status);
