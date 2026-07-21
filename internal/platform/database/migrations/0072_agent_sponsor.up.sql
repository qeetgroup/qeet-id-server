-- Agent sponsor model: every agent is tied to a named human owner, so an
-- offboarding admin can find and reassign (or suspend) what they sponsored
-- instead of leaving orphaned, unaccountable non-human identities behind.
-- Nullable at the schema level so existing rows (created before this column
-- existed) don't break; the service layer requires it on new creates.
ALTER TABLE auth.agents ADD COLUMN IF NOT EXISTS sponsor_user_id UUID REFERENCES "user".users(id);
CREATE INDEX IF NOT EXISTS idx_agents_sponsor ON auth.agents (tenant_id, sponsor_user_id);
