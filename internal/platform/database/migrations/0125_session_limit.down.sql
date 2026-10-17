ALTER TABLE tenant.security_policies DROP COLUMN IF EXISTS session_limit_action;
ALTER TABLE tenant.security_policies DROP COLUMN IF EXISTS max_sessions;
