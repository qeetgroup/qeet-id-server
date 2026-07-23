-- 0053_bot_detection — bot telemetry + per-tenant config (admin "Threats → Bots").
-- Detect-only: score/verdict are logged but the auth path is not hard-blocked, so a legit-but-unusual client is never locked out by a heuristic.
CREATE TABLE auth.bot_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    ip          INET,
    user_agent  TEXT NOT NULL DEFAULT '',
    score       REAL NOT NULL,
    verdict     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bot_events_tenant_created
    ON auth.bot_events (tenant_id, created_at DESC);

-- One row per tenant; absent row = defaults (see bot.DefaultSettings).
CREATE TABLE auth.bot_settings (
    tenant_id       UUID PRIMARY KEY,
    ua_check        BOOLEAN NOT NULL DEFAULT true,
    honeypot        BOOLEAN NOT NULL DEFAULT true,
    captcha         BOOLEAN NOT NULL DEFAULT false,
    signature       BOOLEAN NOT NULL DEFAULT false,
    score_threshold REAL NOT NULL DEFAULT 0.70,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
