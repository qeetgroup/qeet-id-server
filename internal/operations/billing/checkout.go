package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
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
func (s *Service) Checkout(ctx context.Context, organizationID uuid.UUID, planCode, currency, country, successURL, cancelURL string) (*CheckoutResult, error) {
	cur, ok := normalizeCurrency(currency)
	if !ok {
		return nil, ErrCurrencyInvalid
	}
	if country != "" && !countryRe.MatchString(country) {
		return nil, ErrCountryInvalid
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
		return nil, ErrPlanNotPriced
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
		return s.activateDirect(ctx, organizationID, planCode, cur, country)
	}

	// Never grant a paid plan for free, unless the operator opted into
	// invoice-only billing, which leaves its invoice open.
	if provider == nil {
		if !s.allowUnpaidActivation {
			return nil, errs.ErrUnprocessable.
				WithMessage("Online payment isn't available for this country or currency yet.").
				WithDetail("no card payment provider is configured to charge " + cur + " for the selected billing country")
		}
		return s.activateDirect(ctx, organizationID, planCode, cur, country)
	}

	// Paid plan with a provider: record a pending checkout and open a payment
	// for the total, tax included, that the invoice will show.
	tr := s.taxFor(ctx, s.q, organizationID, amt, country)
	return s.openCheckout(ctx, provider, dbgen.InsertBillingCheckoutParams{
		OrganizationID:     organizationID,
		Provider:           provider.Name(),
		PlanCode:           planCode,
		Currency:           cur,
		AmountMinor:        tr.TotalMinor,
		TaxableAmountMinor: tr.TaxableMinor,
		TaxAmountMinor:     tr.TaxMinor,
		TaxRateBps:         int32(tr.RateBps), // #nosec G115 -- operator-set GST rate in basis points
		TaxType:            tr.Type,
		PlaceOfSupply:      tr.PlaceOfSupply,
	}, planName, successURL, cancelURL)
}

// openCheckout records the pending checkout in and opens the provider's hosted
// payment for its amount, under name.
func (s *Service) openCheckout(ctx context.Context, provider PaymentProvider, in dbgen.InsertBillingCheckoutParams, name, successURL, cancelURL string) (*CheckoutResult, error) {
	checkoutID, err := s.q.InsertBillingCheckout(ctx, in)
	if err != nil {
		return nil, err
	}
	redirectURL, providerRef, err := provider.CreateCheckout(ctx, CheckoutInput{
		Ref:         checkoutID.String(),
		PlanName:    name,
		Currency:    in.Currency,
		AmountMinor: in.AmountMinor,
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
// plans and invoice-only billing, taxing by country when the billing profile
// names none.
func (s *Service) activateDirect(ctx context.Context, organizationID uuid.UUID, planCode, currency, country string) (*CheckoutResult, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := s.activateUnpaid(ctx, s.q.WithTx(tx), organizationID, planCode, currency, country); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &CheckoutResult{Status: "active"}, nil
}

// CompleteCheckout activates the plan behind a paid checkout, organization or signup,
// or settles the invoice it paid, recording method, what it was paid with, when
// the provider said. The pending-to-completed transition is claimed atomically,
// so webhook retries activate it exactly once; an unknown ref is a no-op.
func (s *Service) CompleteCheckout(ctx context.Context, ref string, method *PaymentMethod) error {
	id, err := uuid.Parse(ref)
	if err != nil {
		return ErrCheckoutRefInvalid
	}
	var recorded []byte
	if method != nil {
		if recorded, err = json.Marshal(method); err != nil {
			return err
		}
	}
	completed, err := s.completeOrganizationCheckout(ctx, id, recorded)
	if err != nil || completed {
		return err
	}
	// Not an organization checkout: it may be a signup checkout, whose organization is
	// created now.
	return s.completeSignupCheckout(ctx, id, recorded)
}

// completeOrganizationCheckout claims a pending organization checkout and, in one
// transaction, settles the invoice it paid or activates its plan. A payment for
// an invoice no longer open buys its plan afresh instead, so it is never lost.
// It reports false, having changed nothing, when id is not a pending organization
// checkout.
func (s *Service) completeOrganizationCheckout(ctx context.Context, id uuid.UUID, method []byte) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CompleteCheckout(ctx, dbgen.CompleteCheckoutParams{ID: id, PaymentMethod: method})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if row.InvoiceID != nil {
		sp, err := tx.Begin(ctx)
		if err != nil {
			return false, err
		}
		err = s.settleInvoice(ctx, sp, row.OrganizationID, *row.InvoiceID, row.ProviderRef, row.Provider)
		if err == nil {
			if err := sp.Commit(ctx); err != nil {
				return false, err
			}
			return true, tx.Commit(ctx)
		}
		if !errors.Is(err, ErrInvoiceNotOpen) && !errors.Is(err, ErrInvoiceNotFound) {
			return false, err
		}
		if err := sp.Rollback(ctx); err != nil {
			return false, err
		}
		slog.Warn("billing: a checkout paid an invoice no longer open; buying its plan instead",
			"checkout_id", id, "invoice_id", *row.InvoiceID)
	}
	charged := checkoutTax(row.AmountMinor, row.TaxableAmountMinor, row.TaxAmountMinor, row.TaxRateBps, row.TaxType, row.PlaceOfSupply)
	if err := s.activatePaid(ctx, tx, row.OrganizationID, row.PlanCode, row.Currency, charged); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// completeSignupCheckout claims a pending signup checkout, creates its
// organization and activates the subscription. An unknown or completed checkout
// is a no-op. If a step fails, the checkout returns to pending, keeping any
// organization already created, so a retry resumes where it stopped.
func (s *Service) completeSignupCheckout(ctx context.Context, id uuid.UUID, method []byte) error {
	if s.orgProvisioner == nil {
		return nil
	}
	c, err := s.q.ClaimSignupCheckout(ctx, dbgen.ClaimSignupCheckoutParams{ID: id, PaymentMethod: method})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // unknown, already completed, or failed — idempotent no-op
	}
	if err != nil {
		return err
	}
	retryLater := func(cause error) error {
		_ = s.q.ReopenSignupCheckout(ctx, id)
		return cause
	}

	var organizationID uuid.UUID
	if c.OrganizationID != nil {
		organizationID = *c.OrganizationID // an earlier attempt created it
	} else {
		if organizationID, err = s.provisionSignupOrg(ctx, c.UserID, c.OrgName, c.OrgSlug, c.Region, c.PlanCode); err != nil {
			return retryLater(err)
		}
		// Recorded at once, so a retry after a later failure reuses this
		// organization rather than creating another. Failing here leaves the
		// checkout completed: a retry would create a second organization.
		if err := s.q.SetSignupCheckoutOrganization(ctx, dbgen.SetSignupCheckoutOrganizationParams{OrganizationID: organizationID, ID: id}); err != nil {
			slog.Error("billing: signup organization created but not recorded", "checkout_id", id, "organization_id", organizationID, "err", err)
			return err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return retryLater(err)
	}
	defer tx.Rollback(ctx)
	charged := checkoutTax(c.AmountMinor, c.TaxableAmountMinor, c.TaxAmountMinor, c.TaxRateBps, c.TaxType, c.PlaceOfSupply)
	if err := s.activatePaid(ctx, tx, organizationID, c.PlanCode, c.Currency, charged); err != nil {
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
	// The organization's plan label is the tier; the subscription keeps the full code
	// (such as "starter_year") so its interval and price are right.
	tier := strings.TrimSuffix(planCode, "_year")
	var organizationID uuid.UUID
	var provErr error
	for attempt := 0; attempt < 5; attempt++ {
		trySlug := slug
		if attempt > 0 {
			trySlug = fmt.Sprintf("%s-%s", slug, uuid.NewString()[:6])
		}
		organizationID, provErr = s.orgProvisioner.ProvisionOrg(ctx, userID, name, trySlug, region, tier)
		if provErr == nil {
			break
		}
		if errors.Is(provErr, errs.ErrOrgSlugTaken) {
			continue // slug collided since staging — try a fresh, unique slug
		}
		break // other (likely transient) error: the checkout is retried
	}
	return organizationID, provErr
}

// StartSignupCheckout opens a hosted payment for a paid plan chosen at signup,
// before the organization exists. It only stages the organization, which
// completeSignupCheckout creates once the payment completes. A free plan returns
// errs.ErrBadRequest; it creates its organization directly.
func (s *Service) StartSignupCheckout(ctx context.Context, ownerID uuid.UUID, in SignupCheckoutInput) (*CheckoutResult, error) {
	cur, ok := normalizeCurrency(in.Currency)
	if !ok {
		return nil, ErrCurrencyInvalid
	}
	if in.Country != "" && !countryRe.MatchString(in.Country) {
		return nil, ErrCountryInvalid
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
		return nil, ErrPlanNotPriced
	}
	// A free plan has nothing to charge.
	if amt == 0 {
		return nil, errs.ErrBadRequest
	}

	// Fail fast if the slug is taken, so we never charge for an organization we
	// cannot create. Creation checks again atomically.
	slugTaken, err := s.q.OrganizationSlugTaken(ctx, in.OrgSlug)
	if err != nil {
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

	// The organization has no billing profile yet, so tax goes by the billing
	// country given, and the provider charges the total.
	tr := computeTax(s.tax, TaxInput{AmountMinor: amt, BuyerCountry: in.Country})
	checkoutID, err := s.q.InsertSignupCheckout(ctx, dbgen.InsertSignupCheckoutParams{
		UserID:             ownerID,
		OrgName:            in.OrgName,
		OrgSlug:            in.OrgSlug,
		Region:             in.Region,
		PlanCode:           in.PlanCode,
		Currency:           cur,
		Country:            in.Country,
		Provider:           provider.Name(),
		AmountMinor:        tr.TotalMinor,
		TaxableAmountMinor: tr.TaxableMinor,
		TaxAmountMinor:     tr.TaxMinor,
		TaxRateBps:         int32(tr.RateBps), // #nosec G115 -- operator-set GST rate in basis points
		TaxType:            tr.Type,
		PlaceOfSupply:      tr.PlaceOfSupply,
	})
	if err != nil {
		return nil, err
	}

	redirectURL, providerRef, err := provider.CreateCheckout(ctx, CheckoutInput{
		Ref:         checkoutID.String(),
		PlanName:    planName,
		Currency:    cur,
		AmountMinor: tr.TotalMinor,
		SuccessURL:  in.SuccessURL,
		CancelURL:   in.CancelURL,
	})
	if err != nil {
		_ = s.q.FailSignupCheckout(ctx, checkoutID)
		return nil, errs.ErrInternalServer.WithMessage("Couldn't start the payment. Please try again.").Wrap(err)
	}
	_ = s.q.SetSignupCheckoutProviderRef(ctx, dbgen.SetSignupCheckoutProviderRefParams{ProviderRef: providerRef, ID: checkoutID})
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
}

// HandleWebhook verifies a provider webhook and, for a successful payment,
// completes its checkout; other events are a no-op. An unknown provider returns
// errs.ErrNotFound and a bad signature ErrWebhookVerificationFailed.
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
		return ErrWebhookVerificationFailed
	}
	if !paid || ref == "" {
		return nil
	}
	// What paid is worth knowing but never worth failing the payment over.
	var method *PaymentMethod
	if reader, ok := prov.(paymentMethodReader); ok {
		if method, err = reader.PaymentMethod(ctx, body); err != nil {
			slog.Warn("billing: payment method not read", "provider", providerName, "err", err)
			method = nil
		}
	}
	return s.CompleteCheckout(ctx, ref, method)
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
		return ErrWebhookVerificationFailed
	}
	if !paid || ref == "" {
		return nil
	}
	// The redirect doesn't say what paid; the webhook, when it arrives, can't
	// add it to a checkout already complete.
	return s.CompleteCheckout(ctx, ref, nil)
}
