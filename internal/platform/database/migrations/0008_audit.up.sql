-- 0008_audit — the audit trail and what is derived from it.
--
-- Each table is headed by the package that owns it. A column marked (0010) is a
-- foreign key into another schema, which 0010_cross_schema_keys adds.

-- internal/operations/audit/anomaly
CREATE TABLE audit.actor_baselines (
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    actor_user_id   UUID NOT NULL,
    event_count     BIGINT NOT NULL DEFAULT 0,
    actions         JSONB NOT NULL DEFAULT '{}'::jsonb,
    hours           JSONB NOT NULL DEFAULT '{}'::jsonb,
    ips             JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, actor_user_id)
);

-- internal/operations/audit/anomaly
CREATE TABLE audit.anomaly_settings (
    organization_id     UUID PRIMARY KEY, -- organization.organizations (0010)
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    score_threshold     DOUBLE PRECISION NOT NULL DEFAULT 0.6,
    min_baseline_events INTEGER NOT NULL DEFAULT 20,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- internal/operations/audit
-- An append-only log. organization_id has no foreign key, so recording an event
-- never locks the organization's row; the organization purge deletes its
-- events in batches. An event of the platform's own chain has no organization_id.
CREATE TABLE audit.events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID,
    actor_user_id   UUID,
    actor_type      TEXT NOT NULL DEFAULT 'user',
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     UUID,
    ip              INET,
    user_agent      TEXT,
    request_id      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hash       CHAR(64),
    row_hash        CHAR(64),
    scored_at       TIMESTAMPTZ,
    chain_shard     SMALLINT NOT NULL DEFAULT 0,
    search_vector   TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, audit.search_text(action, resource_type, actor_type, user_agent, ip, metadata))) STORED,
    CONSTRAINT audit_events_hash_both_or_neither CHECK ((prev_hash IS NULL) = (row_hash IS NULL))
);
CREATE INDEX idx_audit_actor ON audit.events (actor_user_id, created_at DESC) WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_chain_tip ON audit.events (organization_id, created_at DESC, id DESC)
    WHERE row_hash IS NOT NULL;
CREATE INDEX idx_audit_events_unscored ON audit.events (created_at, id) WHERE scored_at IS NULL;
CREATE INDEX idx_audit_platform_chain ON audit.events (chain_shard, created_at DESC, id DESC)
    WHERE organization_id IS NULL AND row_hash IS NOT NULL;
CREATE INDEX idx_audit_resource ON audit.events (resource_type, resource_id, created_at DESC);
CREATE INDEX idx_audit_search_vector ON audit.events USING gin (search_vector);
CREATE INDEX idx_audit_sign_ins ON audit.events (organization_id, created_at) INCLUDE (actor_user_id)
    WHERE action = 'auth.login_succeeded';
CREATE INDEX idx_audit_organization_time ON audit.events (organization_id, created_at DESC);

-- internal/operations/audit/anomaly
CREATE TABLE audit.anomalies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL, -- organization.organizations (0010)
    event_id        UUID NOT NULL REFERENCES audit.events (id) ON DELETE CASCADE,
    actor_user_id   UUID,
    score           DOUBLE PRECISION NOT NULL,
    reasons         TEXT[] NOT NULL DEFAULT '{}'::text[],
    status          TEXT NOT NULL DEFAULT 'open',
    resolved_at     TIMESTAMPTZ,
    resolved_by     UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT anomalies_status_check CHECK (status IN ('open', 'resolved'))
);
CREATE UNIQUE INDEX idx_audit_anomalies_event ON audit.anomalies (event_id);
CREATE INDEX idx_audit_anomalies_organization_open ON audit.anomalies (organization_id, created_at DESC)
    WHERE status = 'open';
