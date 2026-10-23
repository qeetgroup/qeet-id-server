package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// CheckoutResult is either an active subscription (a free plan, or a paid plan
// under invoice-only billing) or a hosted-checkout URL to send the payer to.
type CheckoutResult struct {
	Status      string `json:"status"`                 // "active" or "checkout"
	CheckoutURL string `json:"checkout_url,omitempty"` // where to send the payer, for "checkout"
	Provider    string `json:"provider,omitempty"`     // the payment provider handling it
}

// SignupCheckoutInput is a paid plan chosen during signup, before the
// organization exists. The organization is created when the payment completes.
type SignupCheckoutInput struct {
	OrgName    string
	OrgSlug    string
	Region     string
	PlanCode   string
	Currency   string
	Country    string
	SuccessURL string
	CancelURL  string
}

// Checkout starts a plan change. A free plan activates at once. A paid plan gets
// a pending checkout and the provider's hosted-payment URL; its webhook later
// calls CompleteCheckout. The provider is chosen by country, else by currency;
// with none, the plan is refused unless invoice-only billing is enabled.
func (s *Service) Checkout(ctx context.Context, tenantID uuid.UUID, planCode, currency, country, successURL, cancelURL string) (*CheckoutResult, error) {
	cur, ok := normalizeCurrency(currency)
	if !ok {
		return nil, errs.ErrBillingCurrencyInvalid
	}
	if country != "" && !countryRe.MatchString(country) {
		return nil, errs.ErrBillingCountryInvalid
	}
	planID, _, planName, err := planByCode(ctx, s.q, planCode)
	if err != nil {
		return nil, err
	}
	amt, priced, err := priceFor(ctx, s.q, planID, cur)
	if err != nil {
		return nil, err
	}
	if !priced {
		return nil, errs.ErrBillingPlanNotPriced
	}

	var provider PaymentProvider
	if s.payments != nil {
		if country != "" {
			provider = s.payments.forCountry(country)
		} else {
			provider = s.payments.forCurrency(cur) // no country given
		}
	}

	// Free plan → nothing to collect, activate directly.
	if amt == 0 {
		return s.activateDirect(ctx, tenantID, planCode, cur)
	}

	// Never grant a paid plan for free, unless the operator opted into
	// invoice-only billing.
	if provider == nil {
		if !s.allowUnpaidActivation {
			return nil, errs.ErrUnprocessable.
				WithMessage("Online payment isn't available for this country or currency yet.").
				WithDetail("no card payment provider is configured to charge " + cur + " for the selected billing country")
		}
		return s.activateDirect(ctx, tenantID, planCode, cur)
	}

	// Paid plan with a provider: record a pending checkout and open a payment.
	checkoutID, err := s.q.InsertBillingCheckout(ctx, dbgen.InsertBillingCheckoutParams{
		TenantID:    tenantID,
		Provider:    provider.Name(),
		PlanCode:    planCode,
		Currency:    cur,
		AmountMinor: amt,
	})
	if err != nil {
		return nil, err
	}
	redirectURL, providerRef, err := provider.CreateCheckout(ctx, CheckoutInput{
		Ref:         checkoutID.String(),
		PlanName:    planName,
		Currency:    cur,
		AmountMinor: amt,
		SuccessURL:  successURL,
		CancelURL:   cancelURL,
	})
	if err != nil {
		_ = s.q.UpdateCheckoutFailed(ctx, checkoutID)
		// Wrap, not WithDetail: err holds the provider's raw response body, which
		// can be large and contains account identifiers. Detail goes to the client;
		// a wrapped cause is only logged.
		return nil, errs.ErrInternalServer.WithMessage("Couldn't start the payment. Please try again.").Wrap(err)
	}
	_ = s.q.UpdateCheckoutProviderRef(ctx, dbgen.UpdateCheckoutProviderRefParams{
		ProviderRef: providerRef,
		ID:          checkoutID,
	})
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
}

// activateDirect changes the plan in one transaction with no payment, for free
// plans and invoice-only billing.
func (s *Service) activateDirect(ctx context.Context, tenantID uuid.UUID, planCode, currency string) (*CheckoutResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.ChangePlan(ctx, tx, tenantID, planCode, currency); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &CheckoutResult{Status: "active"}, nil
}

// CompleteCheckout activates the plan behind a paid checkout, tenant or signup.
// The pending-to-completed transition is claimed atomically, so webhook retries
// activate it exactly once; an unknown ref is a no-op.
func (s *Service) CompleteCheckout(ctx context.Context, ref string) error {
	id, err := uuid.Parse(ref)
	if err != nil {
		return errs.ErrBillingCheckoutRefInvalid
	}
	completed, err := s.completeTenantCheckout(ctx, id)
	if err != nil || completed {
		return err
	}
	// Not a tenant checkout: it may be a signup checkout, whose organization is
	// created now.
	return s.completeSignupCheckout(ctx, id)
}

// completeTenantCheckout claims a pending tenant checkout and activates its
// plan in one transaction. It reports false, having changed nothing, when id
// is not a pending tenant checkout.
func (s *Service) completeTenantCheckout(ctx context.Context, id uuid.UUID) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CompleteCheckout(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := s.ChangePlan(ctx, tx, row.TenantID, row.PlanCode, row.Currency); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// completeSignupCheckout claims a pending signup checkout, creates its
// organization and activates the subscription. An unknown or completed checkout
// is a no-op. If a step fails, the checkout returns to pending, keeping any
// organization already created, so a retry resumes where it stopped.
func (s *Service) completeSignupCheckout(ctx context.Context, id uuid.UUID) error {
	if s.orgProvisioner == nil {
		return nil
	}
	var (
		userID                                     uuid.UUID
		name, slug, region, planCode, currencyCode string
		created                                    *uuid.UUID
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE tenant.signup_checkouts
		SET status = 'completed', completed_at = NOW()
		WHERE id = $1 AND status = 'pending'
		RETURNING user_id, org_name, org_slug, region, plan_code, currency, tenant_id`,
		id,
	).Scan(&userID, &name, &slug, &region, &planCode, &currencyCode, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // unknown, already completed, or failed — idempotent no-op
	}
	if err != nil {
		return err
	}
	retryLater := func(cause error) error {
		_, _ = s.pool.Exec(ctx,
			`UPDATE tenant.signup_checkouts SET status = 'pending', completed_at = NULL WHERE id = $1`, id)
		return cause
	}

	var tenantID uuid.UUID
	if created != nil {
		tenantID = *created // an earlier attempt created it
	} else {
		if tenantID, err = s.provisionSignupOrg(ctx, userID, name, slug, region, planCode); err != nil {
			return retryLater(err)
		}
		// Recorded at once, so a retry after a later failure reuses this
		// organization rather than creating another. Failing here leaves the
		// checkout completed: a retry would create a second organization.
		if _, err := s.pool.Exec(ctx, `UPDATE tenant.signup_checkouts SET tenant_id = $1 WHERE id = $2`, tenantID, id); err != nil {
			slog.Error("billing: signup organization created but not recorded", "checkout_id", id, "tenant_id", tenantID, "err", err)
			return err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return retryLater(err)
	}
	defer tx.Rollback(ctx)
	if _, err := s.ChangePlan(ctx, tx, tenantID, planCode, currencyCode); err != nil {
		return retryLater(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return retryLater(err)
	}
	return nil
}

// provisionSignupOrg creates a signup checkout's organization, with the plan's
// tier as its label. The slug may have been taken since the checkout was
// staged, so a taken one is retried with a unique suffix: the customer has
// already paid.
func (s *Service) provisionSignupOrg(ctx context.Context, userID uuid.UUID, name, slug, region, planCode string) (uuid.UUID, error) {
	// The tenant's plan label is the tier; the subscription keeps the full code
	// (such as "starter_year") so its interval and price are right.
	tier := strings.TrimSuffix(planCode, "_year")
	var tenantID uuid.UUID
	var provErr error
	for attempt := 0; attempt < 5; attempt++ {
		trySlug := slug
		if attempt > 0 {
			trySlug = fmt.Sprintf("%s-%s", slug, uuid.NewString()[:6])
		}
		tenantID, provErr = s.orgProvisioner.ProvisionOrg(ctx, userID, name, trySlug, region, tier)
		if provErr == nil {
			break
		}
		if errors.Is(provErr, errs.ErrOrgSlugTaken) {
			continue // slug collided since staging — try a fresh, unique slug
		}
		break // other (likely transient) error: the checkout is retried
	}
	return tenantID, provErr
}

// StartSignupCheckout opens a hosted payment for a paid plan chosen at signup,
// before the organization exists. It only stages the organization, which
// completeSignupCheckout creates once the payment completes. A free plan returns
// errs.ErrBadRequest; it creates its organization directly.
func (s *Service) StartSignupCheckout(ctx context.Context, ownerID uuid.UUID, in SignupCheckoutInput) (*CheckoutResult, error) {
	cur, ok := normalizeCurrency(in.Currency)
	if !ok {
		return nil, errs.ErrBillingCurrencyInvalid
	}
	if in.Country != "" && !countryRe.MatchString(in.Country) {
		return nil, errs.ErrBillingCountryInvalid
	}
	planID, _, planName, err := planByCode(ctx, s.q, in.PlanCode)
	if err != nil {
		return nil, err
	}
	amt, priced, err := priceFor(ctx, s.q, planID, cur)
	if err != nil {
		return nil, err
	}
	if !priced {
		return nil, errs.ErrBillingPlanNotPriced
	}
	// A free plan has nothing to charge.
	if amt == 0 {
		return nil, errs.ErrBadRequest
	}

	// Fail fast if the slug is taken, so we never charge for an organization we
	// cannot create. Creation checks again atomically.
	var slugTaken bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM tenant.tenants WHERE slug = $1)`, in.OrgSlug).Scan(&slugTaken); err != nil {
		return nil, err
	}
	if slugTaken {
		return nil, errs.ErrOrgSlugTaken
	}

	var provider PaymentProvider
	if s.payments != nil {
		if in.Country != "" {
			provider = s.payments.forCountry(in.Country)
		} else {
			provider = s.payments.forCurrency(cur)
		}
	}
	if provider == nil {
		return nil, errs.ErrUnprocessable.
			WithMessage("Online payment isn't available for this country or currency yet.").
			WithDetail("no card payment provider is configured to charge " + cur + " for the selected billing country")
	}

	var checkoutID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.signup_checkouts
			(user_id, org_name, org_slug, region, plan_code, currency, country, provider, amount_minor)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		ownerID, in.OrgName, in.OrgSlug, in.Region, in.PlanCode, cur, in.Country, provider.Name(), amt,
	).Scan(&checkoutID); err != nil {
		return nil, err
	}

	redirectURL, providerRef, err := provider.CreateCheckout(ctx, CheckoutInput{
		Ref:         checkoutID.String(),
		PlanName:    planName,
		Currency:    cur,
		AmountMinor: amt,
		SuccessURL:  in.SuccessURL,
		CancelURL:   in.CancelURL,
	})
	if err != nil {
		_, _ = s.pool.Exec(ctx, `UPDATE tenant.signup_checkouts SET status = 'failed' WHERE id = $1`, checkoutID)
		return nil, errs.ErrInternalServer.WithMessage("Couldn't start the payment. Please try again.").Wrap(err)
	}
	_, _ = s.pool.Exec(ctx, `UPDATE tenant.signup_checkouts SET provider_ref = $1 WHERE id = $2`, providerRef, checkoutID)
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
}

// HandleWebhook verifies a provider webhook and, for a successful payment,
// completes its checkout; other events are a no-op. An unknown provider returns
// errs.ErrNotFound and a bad signature errs.ErrBillingWebhookVerificationFailed.
func (s *Service) HandleWebhook(ctx context.Context, providerName string, body []byte, signature string) error {
	if s.payments == nil {
		return errs.ErrNotFound
	}
	prov := s.payments.byName(providerName)
	if prov == nil {
		return errs.ErrNotFound
	}
	ref, paid, err := prov.VerifyAndParse(body, signature)
	if err != nil {
		return errs.ErrBillingWebhookVerificationFailed
	}
	if !paid || ref == "" {
		return nil
	}
	return s.CompleteCheckout(ctx, ref)
}

// WebhookSignatureHeader returns the webhook signature header of a provider, or
// "" if the provider is not configured.
func (s *Service) WebhookSignatureHeader(providerName string) string {
	if s.payments == nil {
		return ""
	}
	if prov := s.payments.byName(providerName); prov != nil {
		return prov.SignatureHeader()
	}
	return ""
}

// CompleteRazorpayCallback verifies a Razorpay payment-link redirect and, if it
// was paid, completes its checkout. It is idempotent with the webhook, and is
// what completes checkouts in local development, which the webhook cannot reach.
func (s *Service) CompleteRazorpayCallback(ctx context.Context, params map[string]string) error {
	if s.payments == nil || s.payments.razorpay == nil {
		return errs.ErrNotFound
	}
	ref, paid, err := s.payments.razorpay.VerifyCallback(params)
	if err != nil {
		return errs.ErrBillingWebhookVerificationFailed
	}
	if !paid || ref == "" {
		return nil
	}
	return s.CompleteCheckout(ctx, ref)
}
