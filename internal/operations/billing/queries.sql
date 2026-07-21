-- Queries for the billing domain.
-- All SQL here is static; there are no dynamic WHERE/SET clauses.

-- name: ListBillingPlans :many
-- Return all active plans in display order (for the public /billing/plans endpoint).
SELECT id, code, name, description, interval, features
FROM platform.billing_plans
WHERE active = TRUE
ORDER BY sort, name;

-- name: ListBillingPlanPrices :many
-- Fetch all plan prices (joined in Go to populate Plan.Prices map).
SELECT plan_id, currency, amount_minor
FROM platform.billing_plan_prices;

-- name: GetBillingPlanByCode :one
-- Look up a plan by its code for subscription/checkout flows.
SELECT id, interval, name
FROM platform.billing_plans
WHERE code = @code AND active = TRUE;

-- name: GetBillingPlanPrice :one
-- Check whether a plan is priced in a given currency and fetch the amount.
SELECT amount_minor
FROM platform.billing_plan_prices
WHERE plan_id = @plan_id AND currency = @currency;

-- name: GetSubscription :one
-- Fetch the current subscription for a tenant, joining plan metadata and the
-- currency-specific price in one round-trip.
SELECT p.code, p.name, p.interval, s.currency, s.status,
       s.current_period_start, s.current_period_end, s.cancel_at_period_end,
       COALESCE(pp.amount_minor, 0) AS amount_minor
FROM tenant.subscriptions s
JOIN platform.billing_plans p ON p.id = s.plan_id
LEFT JOIN platform.billing_plan_prices pp
    ON pp.plan_id = s.plan_id AND pp.currency = s.currency
WHERE s.tenant_id = @tenant_id;

-- name: UpsertSubscription :exec
-- Create or replace the tenant's subscription (one row per tenant).
INSERT INTO tenant.subscriptions
    (tenant_id, plan_id, currency, status,
     current_period_start, current_period_end, cancel_at_period_end, updated_at)
VALUES (@tenant_id, @plan_id, @currency, 'active', @period_start, @period_end, FALSE, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    plan_id              = EXCLUDED.plan_id,
    currency             = EXCLUDED.currency,
    status               = 'active',
    current_period_start = EXCLUDED.current_period_start,
    current_period_end   = EXCLUDED.current_period_end,
    cancel_at_period_end = FALSE,
    updated_at           = NOW();

-- name: InsertInvoice :exec
-- Issue an invoice for one billing period (zero-amount plans still get a record).
INSERT INTO tenant.invoices
    (tenant_id, plan_code, currency, amount_minor, status, period_start, period_end)
VALUES (@tenant_id, @plan_code, @currency, @amount_minor, 'paid', @period_start, @period_end);

-- name: CancelSubscription :execrows
-- Mark the subscription to cancel at end of current period.  Returns 0 rows
-- affected when no active subscription exists.
UPDATE tenant.subscriptions
SET cancel_at_period_end = TRUE, updated_at = NOW()
WHERE tenant_id = @tenant_id;

-- name: InsertBillingCheckout :one
-- Create a pending card-payment checkout row and return its id, which is
-- passed to the provider as client_reference_id for webhook correlation.
INSERT INTO tenant.billing_checkouts
    (tenant_id, provider, plan_code, currency, amount_minor)
VALUES (@tenant_id, @provider, @plan_code, @currency, @amount_minor)
RETURNING id;

-- name: UpdateCheckoutFailed :exec
-- Mark a checkout as failed when the provider call itself errors out.
UPDATE tenant.billing_checkouts
SET status = 'failed'
WHERE id = @id;

-- name: UpdateCheckoutProviderRef :exec
-- Store the provider's own checkout reference after a successful CreateCheckout call.
UPDATE tenant.billing_checkouts
SET provider_ref = @provider_ref
WHERE id = @id;

-- name: CompleteCheckout :one
-- Atomically flip a pending checkout to completed and return the plan details
-- needed to activate the subscription.  Returns ErrNoRows when the checkout is
-- already completed, failed, or unknown — callers treat that as an idempotent no-op.
UPDATE tenant.billing_checkouts
SET status = 'completed', completed_at = NOW()
WHERE id = @id AND status = 'pending'
RETURNING tenant_id, plan_code, currency;

-- name: ListInvoices :many
-- Return the tenant's billing history, most recent first.
SELECT id, plan_code, currency, amount_minor, status, period_start, period_end, issued_at
FROM tenant.invoices
WHERE tenant_id = @tenant_id
ORDER BY issued_at DESC
LIMIT 100;

-- name: UpsertBillingPlan :one
-- Idempotent seed upsert for the built-in plan catalogue.
INSERT INTO platform.billing_plans
    (code, name, description, interval, features, sort)
VALUES (@code, @name, @description, @interval, @features, @sort)
ON CONFLICT (code) DO UPDATE SET
    name        = EXCLUDED.name,
    description = EXCLUDED.description,
    interval    = EXCLUDED.interval,
    features    = EXCLUDED.features,
    sort        = EXCLUDED.sort
RETURNING id;

-- name: UpsertBillingPlanPrice :exec
-- Idempotent seed upsert for per-currency plan pricing.
INSERT INTO platform.billing_plan_prices (plan_id, currency, amount_minor)
VALUES (@plan_id, @currency, @amount_minor)
ON CONFLICT (plan_id, currency) DO UPDATE SET
    amount_minor = EXCLUDED.amount_minor;
