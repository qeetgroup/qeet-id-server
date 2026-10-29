-- 0220_webhook_attempts — every attempt to deliver a webhook, with its answer
-- and how long it took, and who disabled a subscription.
ALTER TABLE tenant.webhook_subscriptions ADD COLUMN IF NOT EXISTS disabled_by UUID;

CREATE TABLE tenant.webhook_delivery_attempts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    delivery_id  UUID NOT NULL REFERENCES tenant.webhook_deliveries(id) ON DELETE CASCADE,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_code  INTEGER,
    duration_ms  INTEGER NOT NULL,
    error        TEXT
);

CREATE INDEX idx_webhook_delivery_attempts_delivery ON tenant.webhook_delivery_attempts (delivery_id, attempted_at);

ALTER TABLE tenant.webhook_delivery_attempts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant.webhook_delivery_attempts
    USING (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant())
    WITH CHECK (platform.current_tenant() IS NULL OR tenant_id = platform.current_tenant());
