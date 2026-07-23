-- 0077_adaptive_risk — two per-tenant signals layered onto the bot-score risk engine (auth.risk_settings), additive; both use a small per-user history table, not a fingerprint/GeoIP subsystem:
--   * impossible_travel_enabled: login from a different country than last-seen, sooner than min_travel_hours. Country is opportunistic (a trusted proxy header like CF-IPCountry); with none configured the signal silently never fires (fail-open) — same "interface in place, live dependency is external ops" pattern as KMS BYOK.
--   * device_reputation_enabled: login from a browser+OS never seen for this user (a coarse proxy — no fingerprinting library).
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
