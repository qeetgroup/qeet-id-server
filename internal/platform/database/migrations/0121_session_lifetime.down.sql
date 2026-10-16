ALTER TABLE auth.oidc_refresh_tokens DROP COLUMN IF EXISTS grant_expires_at;
ALTER TABLE auth.sessions DROP COLUMN IF EXISTS idle_timeout;
ALTER TABLE auth.sessions DROP COLUMN IF EXISTS expires_at;
ALTER TABLE tenant.security_policies DROP COLUMN IF EXISTS session_idle_timeout;
