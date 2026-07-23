-- 0052_security_events — append-only anomaly events (admin "Threats → Anomalies").
-- No hard FKs, so a detection write is never blocked by a racing delete; type/severity/status are open strings so new detections need no schema change.
CREATE TABLE auth.security_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL,
    user_id     UUID,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    detail      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    ip          INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_security_events_tenant_created
    ON auth.security_events (tenant_id, created_at DESC);
