-- 0057_billing_checkouts — pending card checkouts (Stripe/Razorpay) completed by the provider's success webhook.
-- Correlation uses this row's id (client_reference_id/notes); status guards against double-activation on webhook retries.
CREATE TABLE tenant.billing_checkouts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    provider_ref TEXT NOT NULL DEFAULT '',
    plan_code    TEXT NOT NULL,
    currency     TEXT NOT NULL,
    amount_minor BIGINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_billing_checkouts_tenant ON tenant.billing_checkouts (tenant_id, created_at DESC);
