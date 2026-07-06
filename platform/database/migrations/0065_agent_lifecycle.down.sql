DROP INDEX IF EXISTS auth.idx_agents_tenant_status;
ALTER TABLE auth.agents DROP COLUMN IF EXISTS status;
