-- Adaptive-MFA depth: two new, independently-togglable-per-tenant signals
-- layered onto the existing bot-score risk engine (auth.risk_settings) —
-- additive checks, not a rewrite. Both read/write a small per-user history
-- table rather than a full device-fingerprint or GeoIP subsystem:
--
--   * impossible_travel_enabled: flags a login from a different country than
--     the user's last-seen one, sooner than min_travel_hours could plausibly
--     allow. Country resolution is opportunistic — sourced from a trusted
--     upstream proxy header (e.g. Cloudflare's CF-IPCountry) if one is
--     configured; with none configured this signal silently never fires
--     (fail-open), the same "interface is in place, live dependency is
--     external ops" pattern as KMS BYOK.
--   * device_reputation_enabled: flags a login from a browser+OS combination
--     never seen before for this user (a coarse device proxy — no
--     fingerprinting library exists or is added by this change).
ALTER TABLE auth.risk_settings
    ADD COLUMN impossible_travel_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN min_travel_hours DOUBLE PRECISION NOT NULL DEFAULT 3,
    ADD COLUMN device_reputation_enabled BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE auth.login_context_history (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    device_key TEXT NOT NULL,
    country    TEXT,
    seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_login_context_user_seen ON auth.login_context_history (user_id, seen_at DESC);
CREATE INDEX idx_login_context_user_device ON auth.login_context_history (user_id, device_key);
