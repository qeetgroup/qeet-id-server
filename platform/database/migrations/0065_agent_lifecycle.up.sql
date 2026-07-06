-- Agent lifecycle state machine: active → suspended → decommissioned.
-- Replaces the boolean disabled_at model with an explicit tri-state so
-- operators can suspend (reversible) or decommission (terminal, one-way) an
-- agent. disabled_at is kept in sync (set when leaving active, cleared on
-- resume) for continuity with anything still reading it.
ALTER TABLE auth.agents
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'decommissioned'));

-- Backfill: previously-disabled agents map to 'suspended' (reversible).
UPDATE auth.agents SET status = 'suspended' WHERE disabled_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agents_tenant_status ON auth.agents (tenant_id, status);
