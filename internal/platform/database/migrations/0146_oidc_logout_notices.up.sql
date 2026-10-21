-- 0146_oidc_logout_notices — tell applications when someone signs out.
--
-- Signing out of the hosted login ended its session and the grants started in
-- it, and told no application, so a person stayed signed in wherever an
-- application keeps its own session. An application may now register where
-- it hears of a sign-out: server to server (OpenID Connect Back-Channel Logout,
-- a signed logout token naming the session) and in the browser (Front-Channel
-- Logout, a page the hosted signed-out page loads).
ALTER TABLE auth.oidc_clients ADD COLUMN backchannel_logout_uri TEXT;
ALTER TABLE auth.oidc_clients ADD COLUMN frontchannel_logout_uri TEXT;

-- One back-channel notice per application per ended session, retried with
-- backoff until delivered or out of attempts (failed_at, recorded for admins).
CREATE TABLE auth.oidc_logout_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants (id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL,
    uri             TEXT NOT NULL,
    logout_token    TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at    TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_oidc_logout_deliveries_due ON auth.oidc_logout_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
