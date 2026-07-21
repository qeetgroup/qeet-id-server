-- Security/anomaly events surfaced in the admin "Threats → Anomalies" screen.
-- Append-only like the audit log (no hard FKs so a detection write can never be
-- blocked by a racing delete); tenant-scoped, with an optional offending user.
-- type/severity/status are open strings so new detections (new_device, geo
-- anomalies, bot verdicts) can be added without a schema change.
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
