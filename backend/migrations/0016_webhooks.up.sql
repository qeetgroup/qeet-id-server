CREATE TABLE tenant.webhook_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    url             TEXT NOT NULL,
    secret          TEXT NOT NULL,        -- shared HMAC secret
    events          TEXT[] NOT NULL DEFAULT '{}',
    disabled_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_tenant ON tenant.webhook_subscriptions (tenant_id);

CREATE TABLE tenant.webhook_deliveries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES tenant.webhook_subscriptions(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status_code     INTEGER,
    response_body   TEXT,
    error           TEXT,
    attempt         INTEGER NOT NULL DEFAULT 0,
    delivered_at    TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_deliv_pending
    ON tenant.webhook_deliveries (next_attempt_at)
    WHERE delivered_at IS NULL;
