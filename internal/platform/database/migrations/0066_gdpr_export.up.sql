-- 0066_gdpr_export — async GDPR data-export requests (queue → sweeper builds payload → poll when status='ready').
-- Payload stored inline as JSONB rather than object storage (no S3-compatible store yet).
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
