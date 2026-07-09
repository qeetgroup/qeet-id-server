-- GDPR data-export requests. Mirrors user.purge_requests' async shape: a
-- request is queued, a background sweeper builds the payload, and the caller
-- polls/downloads once status = 'ready'. The payload is stored inline as JSONB
-- rather than in object storage since no S3-compatible blob store exists yet.
CREATE TABLE "user".export_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id),
    user_id         UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    requested_by    UUID,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'ready', 'failed')),
    payload         JSONB,
    error           TEXT,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_export_requests_tenant ON "user".export_requests (tenant_id, created_at DESC);
CREATE INDEX idx_export_requests_pending ON "user".export_requests (status) WHERE status = 'pending';
