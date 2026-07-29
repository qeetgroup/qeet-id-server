-- 0084_signup_checkouts — paid plan checkouts started BEFORE an organization exists.
-- A user who picks a paid plan during signup has no tenant yet, and we must not
-- create the organization until the payment succeeds (an abandoned payment should
-- leave nothing behind). So the chosen org spec is staged here and the tenant is
-- created only when the provider's success webhook completes the checkout.
-- Free plans don't use this path — they create the org directly (no payment).
CREATE TABLE tenant.signup_checkouts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL,
    org_name     TEXT NOT NULL,
    org_slug     TEXT NOT NULL,
    region       TEXT NOT NULL DEFAULT '',
    plan_code    TEXT NOT NULL,
    currency     TEXT NOT NULL,
    country      TEXT NOT NULL DEFAULT '',
    provider     TEXT NOT NULL,
    provider_ref TEXT NOT NULL DEFAULT '',
    amount_minor BIGINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending', -- pending | completed | failed
    tenant_id    UUID,                            -- set to the created org on completion
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_signup_checkouts_user ON tenant.signup_checkouts (user_id, created_at DESC);
