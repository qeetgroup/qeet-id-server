-- GDPR right-to-erasure: a request enters in 'pending'; a background job
-- purges PII after the grace period; the row is kept as a tombstone for
-- audit.
CREATE TABLE "user".purge_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES "user".users(id) ON DELETE CASCADE,
    requested_by    UUID,
    reason          TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'cancelled')),
    grace_until     TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_purge_pending ON "user".purge_requests (grace_until) WHERE status = 'pending';
