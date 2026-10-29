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
       s.trial_end, s.ended_at,
       COALESCE(pp.amount_minor, 0) AS amount_minor
FROM tenant.subscriptions s
JOIN platform.billing_plans p ON p.id = s.plan_id
LEFT JOIN platform.billing_plan_prices pp
    ON pp.plan_id = s.plan_id AND pp.currency = s.currency
WHERE s.tenant_id = @tenant_id;

-- name: InsertTrialSubscription :exec
-- Start a no-card trial: creates a trialing subscription that reverts to free
-- at trial_end unless it converts to paid. Fails on conflict (one trial/org) —
-- callers check eligibility first.
INSERT INTO tenant.subscriptions
    (tenant_id, plan_id, currency, status,
     current_period_start, current_period_end, trial_end, cancel_at_period_end)
VALUES (@tenant_id, @plan_id, @currency, 'trialing', NOW(), @trial_end, @trial_end, FALSE);

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
    ended_at             = NULL,
    updated_at           = NOW();

-- name: SwitchSubscriptionPlan :exec
-- Move the tenant's subscription to another plan within the period it has paid
-- for: the period and currency stay, and no invoice is issued.
UPDATE tenant.subscriptions
SET plan_id = @plan_id, cancel_at_period_end = FALSE, updated_at = NOW()
WHERE tenant_id = @tenant_id;

-- name: InsertInvoice :one
-- Issue an invoice for one billing period (zero-amount plans still get a record).
-- amount_minor is the total charged (taxable + tax); status is 'paid' when a
-- payment was captured or nothing is owed, else 'open', due at due_at.
INSERT INTO tenant.invoices
    (tenant_id, plan_code, currency, amount_minor, status, period_start, period_end,
     taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply,
     invoice_number, kind, due_at, paid_at, billed_to, supplier_gstin, sac)
VALUES (@tenant_id, @plan_code, @currency, @amount_minor, @status, @period_start, @period_end,
        @taxable_amount_minor, @tax_amount_minor, @tax_rate_bps, @tax_type, @place_of_supply,
        sqlc.narg(invoice_number), @kind, sqlc.narg(due_at),
        CASE WHEN @status::text = 'paid' THEN NOW() END, @billed_to, @supplier_gstin, @sac)
RETURNING id;

-- name: NextInvoiceNumber :one
-- Take the next number of a financial year's invoice series. The row stays
-- locked until the issuing transaction ends, so the numbers have no gaps.
INSERT INTO platform.invoice_number_series (financial_year, last_number)
VALUES (@financial_year, 1)
ON CONFLICT (financial_year) DO UPDATE
    SET last_number = platform.invoice_number_series.last_number + 1
RETURNING last_number;

-- name: GetBillingProfile :one
-- Fetch a tenant's billing & tax details (returns no rows until first save).
SELECT tenant_id, legal_name, billing_email, address_line1, address_line2, city,
       state, postal_code, country, tax_id_type, tax_id, updated_at
FROM tenant.billing_profiles WHERE tenant_id = @tenant_id;

-- name: UpsertBillingProfile :exec
-- Create or replace a tenant's billing & tax details (one row per tenant).
INSERT INTO tenant.billing_profiles
    (tenant_id, legal_name, billing_email, address_line1, address_line2, city,
     state, postal_code, country, tax_id_type, tax_id, updated_at)
VALUES (@tenant_id, @legal_name, @billing_email, @address_line1, @address_line2,
        @city, @state, @postal_code, @country, @tax_id_type, @tax_id, NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    legal_name    = EXCLUDED.legal_name,
    billing_email = EXCLUDED.billing_email,
    address_line1 = EXCLUDED.address_line1,
    address_line2 = EXCLUDED.address_line2,
    city          = EXCLUDED.city,
    state         = EXCLUDED.state,
    postal_code   = EXCLUDED.postal_code,
    country       = EXCLUDED.country,
    tax_id_type   = EXCLUDED.tax_id_type,
    tax_id        = EXCLUDED.tax_id,
    updated_at    = NOW();

-- name: SetTenantPlan :exec
-- Keep the tenant's plan label (tenant.tenants.plan) in sync with its
-- subscription tier. Billing is the only writer of that column now that the
-- tenant PATCH no longer accepts it, so the label can't drift from what's paid.
-- Runs on the caller's tx, alongside UpsertSubscription.
UPDATE tenant.tenants
SET plan = @plan, updated_at = NOW()
WHERE id = @tenant_id AND deleted_at IS NULL;

-- name: CancelSubscription :execrows
-- Mark the subscription to cancel at end of current period.  Returns 0 rows
-- affected when no subscription that hasn't ended exists.
UPDATE tenant.subscriptions
SET cancel_at_period_end = TRUE, updated_at = NOW()
WHERE tenant_id = @tenant_id AND status <> 'canceled';

-- name: InsertBillingCheckout :one
-- Create a pending card-payment checkout row and return its id, which is
-- passed to the provider as client_reference_id for webhook correlation.
-- amount_minor is the total the provider charges (taxable + tax). invoice_id
-- is set when the checkout pays an open invoice rather than buying a plan.
INSERT INTO tenant.billing_checkouts
    (tenant_id, provider, plan_code, currency, amount_minor,
     taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply, invoice_id)
VALUES (@tenant_id, @provider, @plan_code, @currency, @amount_minor,
        @taxable_amount_minor, @tax_amount_minor, @tax_rate_bps, @tax_type, @place_of_supply,
        sqlc.narg(invoice_id))
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
-- needed to activate the subscription, with what it charged.  Returns ErrNoRows
-- when the checkout is already completed, failed, or unknown — callers treat
-- that as an idempotent no-op.
UPDATE tenant.billing_checkouts
SET status = 'completed', completed_at = NOW(), payment_method = sqlc.narg(payment_method)
WHERE id = @id AND status = 'pending'
RETURNING tenant_id, plan_code, currency, amount_minor,
          taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply,
          invoice_id, provider, provider_ref;

-- name: ListInvoices :many
-- Return the tenant's billing history, most recent first.
SELECT id, plan_code, currency, amount_minor, status, period_start, period_end, issued_at,
       taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply,
       invoice_number, kind, due_at, paid_at, billed_to, supplier_gstin, sac, emailed_at
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

-- ==========================================================================
-- Period ends, renewal and settling invoices
-- ==========================================================================

-- name: DueSubscriptions :many
-- The organisations whose trial or period has ended, or whose renewal went
-- unpaid past lapsed_before, oldest first.
SELECT tenant_id FROM tenant.subscriptions
WHERE (status = 'trialing' AND trial_end <= @now::timestamptz)
   OR (status = 'active' AND current_period_end <= @now::timestamptz)
   OR (status = 'past_due' AND (cancel_at_period_end OR current_period_end <= @lapsed_before::timestamptz))
ORDER BY current_period_end
LIMIT 200;

-- name: LockSubscription :one
-- The tenant's subscription with its plan and price, locked for a change.
SELECT p.code, p.interval, s.currency, s.status, s.current_period_start, s.current_period_end,
       s.cancel_at_period_end, s.trial_end, COALESCE(pp.amount_minor, 0) AS amount_minor
FROM tenant.subscriptions s
JOIN platform.billing_plans p ON p.id = s.plan_id
LEFT JOIN platform.billing_plan_prices pp ON pp.plan_id = s.plan_id AND pp.currency = s.currency
WHERE s.tenant_id = @tenant_id
FOR UPDATE OF s;

-- name: EndSubscription :exec
UPDATE tenant.subscriptions SET status = 'canceled', ended_at = NOW(), updated_at = NOW()
WHERE tenant_id = @tenant_id;

-- name: SetSubscriptionPastDue :exec
UPDATE tenant.subscriptions SET status = 'past_due', updated_at = NOW()
WHERE tenant_id = @tenant_id;

-- name: RenewSubscription :exec
-- Start the next period.
UPDATE tenant.subscriptions
SET status = 'active', current_period_start = @period_start, current_period_end = @period_end, updated_at = NOW()
WHERE tenant_id = @tenant_id;

-- name: VoidOpenRenewals :execrows
-- A renewal no longer owed: the subscription ended, or a checkout replaced it.
UPDATE tenant.invoices SET status = 'void'
WHERE tenant_id = @tenant_id AND kind = 'renewal' AND status = 'open';

-- name: LockInvoice :one
SELECT id, tenant_id, kind, status, invoice_number, plan_code, currency, amount_minor,
       taxable_amount_minor, tax_amount_minor, tax_rate_bps, tax_type, place_of_supply,
       period_start, period_end
FROM tenant.invoices WHERE id = @id AND tenant_id = @tenant_id
FOR UPDATE;

-- name: InvoiceTenant :one
-- The organisation an invoice belongs to, for the operator's settle command.
SELECT tenant_id FROM tenant.invoices WHERE id = @id;

-- name: SettleInvoice :exec
UPDATE tenant.invoices SET status = 'paid', paid_at = NOW(), payment_reference = @payment_reference
WHERE id = @id AND tenant_id = @tenant_id;

-- name: ClaimInvoiceEmails :many
-- Claim recently issued invoices not yet emailed to the billing address they
-- were billed to. A send that fails releases its claim.
UPDATE tenant.invoices i SET emailed_at = NOW()
WHERE i.id IN (
    SELECT c.id FROM tenant.invoices c
    WHERE c.emailed_at IS NULL AND c.amount_minor > 0
      AND COALESCE(c.billed_to->>'billing_email', '') <> ''
      AND c.issued_at > NOW() - INTERVAL '1 day'
    ORDER BY c.issued_at
    LIMIT 100
    FOR UPDATE SKIP LOCKED)
RETURNING i.id, i.tenant_id, i.invoice_number, i.plan_code, i.currency, i.amount_minor, i.status,
          i.period_start, i.period_end, i.due_at, i.billed_to;

-- name: ReleaseInvoiceEmail :exec
UPDATE tenant.invoices SET emailed_at = NULL WHERE id = @id AND tenant_id = @tenant_id;

-- name: LatestPaymentMethod :one
-- What the organisation's most recent completed checkout was paid with.
SELECT m.provider, m.payment_method, m.completed_at FROM (
    SELECT c.provider, c.payment_method, c.completed_at FROM tenant.billing_checkouts c
    WHERE c.tenant_id = @tenant_id AND c.status = 'completed' AND c.payment_method IS NOT NULL
    UNION ALL
    SELECT sc.provider, sc.payment_method, sc.completed_at FROM tenant.signup_checkouts sc
    WHERE sc.tenant_id = @tenant_id AND sc.status = 'completed' AND sc.payment_method IS NOT NULL
) m
ORDER BY m.completed_at DESC
LIMIT 1;
