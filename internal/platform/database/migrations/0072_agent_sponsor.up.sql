-- 0072_agent_sponsor — tie each agent to a human owner so offboarding can find/reassign what they sponsored.
-- Nullable at the schema level so pre-existing rows don't break; the service layer requires it on new creates.
ALTER TABLE auth.agents ADD COLUMN IF NOT EXISTS sponsor_user_id UUID REFERENCES "user".users(id);
CREATE INDEX IF NOT EXISTS idx_agents_sponsor ON auth.agents (tenant_id, sponsor_user_id);
