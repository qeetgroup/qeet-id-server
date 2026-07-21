-- Audit intelligence: a behavioral baseline per (tenant, actor) built from
-- the existing hash-chained audit.events log, scored against new events by a
-- background sweep to flag deviations (a first-time action type, an unusual
-- hour, a new IP) as anomalies for admin review.
--
-- scored_at marks a row as processed by the sweep — mirrors the "process
-- exactly once" pattern platform.outbox already uses (published_at IS NULL),
-- rather than a separate watermark/cursor table. It is NOT part of the
-- hash-chain's canonical field set (see audit.go's canonicalRow), so adding
-- and later updating it never invalidates chain verification.
ALTER TABLE audit.events ADD COLUMN scored_at TIMESTAMPTZ;
CREATE INDEX idx_audit_events_unscored ON audit.events (created_at, id) WHERE scored_at IS NULL;

-- One row per (tenant, actor): rolling counters the scorer both reads (to
-- score the incoming event against history) and writes (to fold the event
-- into history afterward). Stored as flexible JSONB counter maps rather than
-- a fully normalized histogram — the counter keys (action strings, "0"-"23"
-- hour buckets, IP strings) are open-ended and queried in bulk, not filtered
-- individually.
CREATE TABLE audit.actor_baselines (
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL,
    event_count   BIGINT NOT NULL DEFAULT 0,
    actions       JSONB NOT NULL DEFAULT '{}',
    hours         JSONB NOT NULL DEFAULT '{}',
    ips           JSONB NOT NULL DEFAULT '{}',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, actor_user_id)
);

CREATE TABLE audit.anomalies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    event_id      UUID NOT NULL REFERENCES audit.events(id) ON DELETE CASCADE,
    actor_user_id UUID,
    score         DOUBLE PRECISION NOT NULL,
    reasons       TEXT[] NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolved_at   TIMESTAMPTZ,
    resolved_by   UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_audit_anomalies_event ON audit.anomalies (event_id);
CREATE INDEX idx_audit_anomalies_tenant_open ON audit.anomalies (tenant_id, created_at DESC) WHERE status = 'open';

-- Per-tenant tuning, mirroring auth.risk_settings' shape (a threshold an
-- admin can adjust) rather than a fixed global constant.
CREATE TABLE audit.anomaly_settings (
    tenant_id           UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    score_threshold     DOUBLE PRECISION NOT NULL DEFAULT 0.6,
    -- Cold-start guard: don't flag anything for an actor until their baseline
    -- has enough history to be trustworthy — otherwise every action from a
    -- brand-new admin looks "100% novel."
    min_baseline_events INTEGER NOT NULL DEFAULT 20,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
