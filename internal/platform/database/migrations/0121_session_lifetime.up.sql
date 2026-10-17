-- 0121_session_lifetime — sessions end by themselves.
--
-- auth.sessions.expires_at: the moment the session ends however active it is,
-- fixed when it opens from the organisation's maximum session age.
-- auth.sessions.idle_timeout: how long it may go unrenewed; it ends at
-- last_seen_at + idle_timeout. Both are taken when the session opens, so a
-- later policy change applies to new sessions only.
--
-- tenant.security_policies.session_idle_timeout: the organisation's idle bound,
-- next to its existing session_max_age.
--
-- auth.oidc_refresh_tokens.grant_expires_at: the moment an application's grant
-- ends however often it is renewed, fixed at the first token from the
-- organisation's maximum session age and carried to every rotated token.
--
-- Existing rows: sessions get the bounds of their organisation (or the platform
-- defaults) counted from when they opened; grants end when their current token
-- does.
ALTER TABLE tenant.security_policies
    ADD COLUMN IF NOT EXISTS session_idle_timeout INTERVAL NOT NULL DEFAULT INTERVAL '24 hours';

ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE auth.sessions ADD COLUMN IF NOT EXISTS idle_timeout INTERVAL;
UPDATE auth.sessions s
SET expires_at = s.created_at + COALESCE(
        (SELECT sp.session_max_age FROM tenant.security_policies sp WHERE sp.tenant_id = s.tenant_id),
        INTERVAL '30 days'),
    idle_timeout = COALESCE(
        (SELECT sp.session_idle_timeout FROM tenant.security_policies sp WHERE sp.tenant_id = s.tenant_id),
        INTERVAL '24 hours')
WHERE s.expires_at IS NULL;
ALTER TABLE auth.sessions
    ALTER COLUMN expires_at SET DEFAULT NOW() + INTERVAL '30 days',
    ALTER COLUMN expires_at SET NOT NULL,
    ALTER COLUMN idle_timeout SET DEFAULT INTERVAL '24 hours',
    ALTER COLUMN idle_timeout SET NOT NULL;

ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN IF NOT EXISTS grant_expires_at TIMESTAMPTZ;
UPDATE auth.oidc_refresh_tokens SET grant_expires_at = expires_at WHERE grant_expires_at IS NULL;
ALTER TABLE auth.oidc_refresh_tokens
    ALTER COLUMN grant_expires_at SET DEFAULT NOW() + INTERVAL '30 days',
    ALTER COLUMN grant_expires_at SET NOT NULL;
