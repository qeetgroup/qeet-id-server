-- 0007_audit — append-only audit event log
CREATE TABLE audit.events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID,
    actor_user_id   UUID,
    actor_type      TEXT NOT NULL DEFAULT 'user',
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     UUID,
    ip              INET,
    user_agent      TEXT,
    request_id      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_tenant_time
    ON audit.events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_resource
    ON audit.events (resource_type, resource_id, created_at DESC);
