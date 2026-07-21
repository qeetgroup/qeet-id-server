DROP INDEX IF EXISTS auth.idx_agents_sponsor;
ALTER TABLE auth.agents DROP COLUMN IF EXISTS sponsor_user_id;
