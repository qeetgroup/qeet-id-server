-- 0038_billing — internal billing (no external processor): plans + per-currency pricing, subscriptions, invoices.
-- Amounts are integer minor units (cents/pence/…); fraction digits applied at display time, so any ISO-4217 currency works.

CREATE TABLE platform.billing_plans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    interval    TEXT NOT NULL DEFAULT 'month' CHECK (interval IN ('month', 'year')),
    features    JSONB NOT NULL DEFAULT '[]'::jsonb,
    sort        INT NOT NULL DEFAULT 0,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE platform.billing_plan_prices (
    plan_id      UUID NOT NULL REFERENCES platform.billing_plans(id) ON DELETE CASCADE,
    currency     TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount_minor BIGINT NOT NULL CHECK (amount_minor >= 0),
    PRIMARY KEY (plan_id, currency)
);

CREATE TABLE tenant.subscriptions (
    tenant_id            UUID PRIMARY KEY REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    plan_id              UUID NOT NULL REFERENCES platform.billing_plans(id),
    currency             TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status               TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'trialing', 'canceled', 'past_due')),
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end   TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tenant.invoices (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenant.tenants(id) ON DELETE CASCADE,
    plan_code    TEXT NOT NULL,
    currency     TEXT NOT NULL,
    amount_minor BIGINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'paid' CHECK (status IN ('paid', 'open', 'void')),
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_invoices_tenant ON tenant.invoices (tenant_id, issued_at DESC);
