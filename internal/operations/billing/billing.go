// Package billing manages subscriptions: a platform plan catalogue with prices
// per currency, one subscription per tenant, invoices, and hosted card checkouts
// through Stripe, Razorpay or a dev sandbox. Money is integer minor units plus
// an ISO 4217 currency code.
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

var countryRe = regexp.MustCompile(`^[A-Za-z]{2}$`)

func normalizeCurrency(c string) (string, bool) {
	c = strings.ToUpper(strings.TrimSpace(c))
	return c, currencyRe.MatchString(c)
}

// Plan is a subscription plan. Prices maps a currency code to the price in
// minor units.
type Plan struct {
	ID          uuid.UUID        `json:"id"`
	Code        string           `json:"code"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Interval    string           `json:"interval"`
	Features    []string         `json:"features"`
	Prices      map[string]int64 `json:"prices"`
}

// Subscription is a tenant's subscription; Status is "none" if it has none.
// TrialEnd is set while Status is "trialing", after which entitlements revert
// to free.
type Subscription struct {
	PlanCode           string     `json:"plan_code"`
	PlanName           string     `json:"plan_name"`
	Currency           string     `json:"currency"`
	AmountMinor        int64      `json:"amount_minor"`
	Interval           string     `json:"interval"`
	Status             string     `json:"status"`
	CurrentPeriodStart *time.Time `json:"current_period_start"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool       `json:"cancel_at_period_end"`
	TrialEnd           *time.Time `json:"trial_end"`
}

// Invoice is an issued invoice. AmountMinor is the total charged: TaxableMinor
// plus TaxMinor.
type Invoice struct {
	ID            uuid.UUID `json:"id"`
	PlanCode      string    `json:"plan_code"`
	Currency      string    `json:"currency"`
	AmountMinor   int64     `json:"amount_minor"`
	TaxableMinor  int64     `json:"taxable_amount_minor"`
	TaxMinor      int64     `json:"tax_amount_minor"`
	TaxRateBps    int       `json:"tax_rate_bps"`
	TaxType       string    `json:"tax_type"`
	PlaceOfSupply string    `json:"place_of_supply"`
	Status        string    `json:"status"`
	PeriodStart   time.Time `json:"period_start"`
	PeriodEnd     time.Time `json:"period_end"`
	IssuedAt      time.Time `json:"issued_at"`
}

// BillingProfile is a tenant's billing & tax details, carried onto invoices.
// TaxIDType is one of "none" | "gstin" (India) | "vat" (EU).
type BillingProfile struct {
	LegalName    string `json:"legal_name"`
	BillingEmail string `json:"billing_email"`
	AddressLine1 string `json:"address_line1"`
	AddressLine2 string `json:"address_line2"`
	City         string `json:"city"`
	State        string `json:"state"`
	PostalCode   string `json:"postal_code"`
	Country      string `json:"country"`
	TaxIDType    string `json:"tax_id_type"`
	TaxID        string `json:"tax_id"`
}

// Service manages plans, subscriptions, invoices and checkouts. Without a card
// provider, Checkout refuses a paid plan unless invoice-only billing is enabled.
// Invoice tax is off until SetTaxConfig configures it.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries

	payments              *Payments      // card providers; nil means none
	allowUnpaidActivation bool           // invoice-only billing; off by default
	orgProvisioner        OrgProvisioner // creates a signup checkout's organization
	tax                   TaxConfig      // invoice tax; the zero value charges none
}

// OrgProvisioner creates an organization (tenant) owned by ownerID. It completes
// a signup checkout, whose organization must not exist until the plan is paid.
type OrgProvisioner interface {
	ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error)
}

// NewService returns a Service with no card providers and tax disabled.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// Pool returns the service's database pool.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPayments sets the card-payment providers.
func (s *Service) SetPayments(p *Payments) { s.payments = p }

// SetAllowUnpaidActivation enables invoice-only billing: Checkout activates a
// paid plan that no card provider can charge, instead of refusing it.
func (s *Service) SetAllowUnpaidActivation(v bool) { s.allowUnpaidActivation = v }

// SetOrgProvisioner sets the organization creator that completes signup
// checkouts.
func (s *Service) SetOrgProvisioner(p OrgProvisioner) { s.orgProvisioner = p }

// SetTaxConfig sets the invoice tax configuration. The zero value charges no
// tax.
func (s *Service) SetTaxConfig(c TaxConfig) { s.tax = c }

// SandboxEnabled reports whether the dev-only sandbox payment provider is active.
func (s *Service) SandboxEnabled() bool { return s.payments.SandboxEnabled() }

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

// --- seeding ---

type builtinPlan struct {
	code, name, description, interval string
	features                          []string
	sort                              int
	prices                            map[string]int64
}

var builtins = []builtinPlan{
	{
		code: "free", name: "Free", description: "For prototypes and early projects.", interval: "month", sort: 1,
		features: []string{"Up to 10,000 monthly active users", "Passkeys, social & password login", "Email magic links & TOTP MFA", "1 organization · RBAC (3 roles)", "7-day audit log", "Community support"},
		prices:   map[string]int64{"USD": 0, "EUR": 0, "GBP": 0, "INR": 0, "JPY": 0, "AUD": 0, "CAD": 0},
	},
	{
		code: "starter", name: "Starter", description: "For teams shipping to production.", interval: "month", sort: 2,
		features: []string{"Up to 25,000 MAU", "All MFA methods (SMS, email, passkey)", "Custom branding & domain", "Webhooks & 30-day audit log", "Email support · 99.9% uptime"},
		prices:   map[string]int64{"USD": 2900, "EUR": 2700, "GBP": 2400, "INR": 240000, "JPY": 4500, "AUD": 4500, "CAD": 3900},
	},
	{
		code: "pro", name: "Pro", description: "For scaling B2B/B2C — no SSO tax.", interval: "month", sort: 3,
		features: []string{"Up to 100,000 MAU (then metered)", "Enterprise SSO — SAML & OIDC included", "RBAC + ABAC & advanced threat protection", "Audit export (90-day) & Qeet AI", "Priority + chat support · 99.95% uptime"},
		prices:   map[string]int64{"USD": 9900, "EUR": 9000, "GBP": 7900, "INR": 800000, "JPY": 15000, "AUD": 15000, "CAD": 13000},
	},
	{
		code: "enterprise", name: "Enterprise", description: "Governance, compliance & control for large orgs.", interval: "month", sort: 4,
		features: []string{"Unlimited MAU & organizations", "SCIM & LDAP directory sync + SSO enforcement", "Conditional access, BYOK & data residency", "Dedicated tenant · SOC 2 / ISO 27001 / HIPAA", "99.99% SLA · named CSM & professional services"},
		prices:   map[string]int64{"USD": 29900, "EUR": 27900, "GBP": 24900, "INR": 2490000, "JPY": 45000, "AUD": 45000, "CAD": 39900},
	},

	// Annual plans of the paid self-serve tiers: the same features, billed yearly
	// at 10× the monthly price. Free and Enterprise (contact sales) have none.
	{
		code: "starter_year", name: "Starter", description: "For teams shipping to production. Billed yearly.", interval: "year", sort: 5,
		features: []string{"Up to 25,000 MAU", "All MFA methods (SMS, email, passkey)", "Custom branding & domain", "Webhooks & 30-day audit log", "Email support · 99.9% uptime"},
		prices:   map[string]int64{"USD": 29000, "EUR": 27000, "GBP": 24000, "INR": 2400000, "JPY": 45000, "AUD": 45000, "CAD": 39000},
	},
	{
		code: "pro_year", name: "Pro", description: "For scaling B2B/B2C — no SSO tax. Billed yearly.", interval: "year", sort: 6,
		features: []string{"Up to 100,000 MAU (then metered)", "Enterprise SSO — SAML & OIDC included", "RBAC + ABAC & advanced threat protection", "Audit export (90-day) & Qeet AI", "Priority + chat support · 99.95% uptime"},
		prices:   map[string]int64{"USD": 99000, "EUR": 90000, "GBP": 79000, "INR": 8000000, "JPY": 150000, "AUD": 150000, "CAD": 130000},
	},
}

// SeedBuiltins upserts the default plan catalogue. It is idempotent, so it runs
// on every boot.
func (s *Service) SeedBuiltins(ctx context.Context) error {
	for _, b := range builtins {
		feat, err := json.Marshal(b.features)
		if err != nil {
			return err
		}
		planID, err := s.q.UpsertBillingPlan(ctx, dbgen.UpsertBillingPlanParams{
			Code:        b.code,
			Name:        b.name,
			Description: b.description,
			Interval:    b.interval,
			Features:    feat,
			Sort:        int32(b.sort),
		})
		if err != nil {
			return err
		}
		for cur, amt := range b.prices {
			if err := s.q.UpsertBillingPlanPrice(ctx, dbgen.UpsertBillingPlanPriceParams{
				PlanID:      planID,
				Currency:    cur,
				AmountMinor: amt,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- plans ---

// ListPlans returns the active plans in display order, with their prices.
func (s *Service) ListPlans(ctx context.Context) ([]Plan, error) {
	planRows, err := s.q.ListBillingPlans(ctx)
	if err != nil {
		return nil, err
	}
	plans := make([]Plan, 0, len(planRows))
	byID := make(map[uuid.UUID]int, len(planRows))
	for _, r := range planRows {
		p := Plan{
			ID:          r.ID,
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Interval:    r.Interval,
			Prices:      map[string]int64{},
		}
		_ = json.Unmarshal(r.Features, &p.Features)
		if p.Features == nil {
			p.Features = []string{}
		}
		byID[p.ID] = len(plans)
		plans = append(plans, p)
	}

	priceRows, err := s.q.ListBillingPlanPrices(ctx)
	if err != nil {
		return nil, err
	}
	for _, pr := range priceRows {
		if idx, ok := byID[pr.PlanID]; ok {
			plans[idx].Prices[pr.Currency] = pr.AmountMinor
		}
	}
	return plans, nil
}

func (s *Service) planByCode(ctx context.Context, code string) (uuid.UUID, string, string, error) {
	row, err := s.q.GetBillingPlanByCode(ctx, code)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", "", errs.ErrBillingPlanNotFound
	}
	if err != nil {
		return uuid.Nil, "", "", err
	}
	return row.ID, row.Interval, row.Name, nil
}

func (s *Service) priceFor(ctx context.Context, planID uuid.UUID, currency string) (int64, bool, error) {
	amt, err := s.q.GetBillingPlanPrice(ctx, dbgen.GetBillingPlanPriceParams{
		PlanID:   planID,
		Currency: currency,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return amt, true, nil
}

// --- subscription ---

// GetSubscription returns the tenant's subscription, or one with Status "none"
// if it has none.
func (s *Service) GetSubscription(ctx context.Context, tenantID uuid.UUID) (*Subscription, error) {
	row, err := s.q.GetSubscription(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Subscription{Status: "none"}, nil
	}
	if err != nil {
		return nil, err
	}
	sub := Subscription{
		PlanCode:           row.Code,
		PlanName:           row.Name,
		Interval:           row.Interval,
		Currency:           row.Currency,
		Status:             row.Status,
		AmountMinor:        row.AmountMinor,
		CancelAtPeriodEnd:  row.CancelAtPeriodEnd,
		CurrentPeriodStart: &row.CurrentPeriodStart,
		CurrentPeriodEnd:   &row.CurrentPeriodEnd,
	}
	if row.TrialEnd.Valid {
		t := row.TrialEnd.Time
		sub.TrialEnd = &t
	}
	return &sub, nil
}

// trialDuration is the length of a no-card trial.
const trialDuration = 14 * 24 * time.Hour

// StartTrial starts a 14-day no-card trial of Starter or Pro for a tenant that
// has never had a subscription. The tier's entitlements last until the trial
// ends, then revert to free unless the tenant pays. No invoice is issued.
func (s *Service) StartTrial(ctx context.Context, tenantID uuid.UUID, planCode, currency string) (*Subscription, error) {
	tier := strings.TrimSuffix(planCode, "_year")
	if tier != "starter" && tier != "pro" {
		return nil, errs.ErrBillingTrialNotEligible.WithMessage("Trials are available for the Starter and Pro plans.")
	}
	cur, ok := normalizeCurrency(currency)
	if !ok {
		cur = "USD"
	}
	existing, err := s.GetSubscription(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if existing.Status != "none" {
		return nil, errs.ErrBillingTrialNotEligible.WithMessage("This organization isn't eligible for a trial.")
	}
	planID, interval, planName, err := s.planByCode(ctx, tier)
	if err != nil {
		return nil, err
	}
	trialEnd := time.Now().UTC().Add(trialDuration)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	qTx := s.q.WithTx(tx)
	if err := qTx.InsertTrialSubscription(ctx, dbgen.InsertTrialSubscriptionParams{
		TenantID: tenantID,
		PlanID:   planID,
		Currency: cur,
		TrialEnd: trialEnd,
	}); err != nil {
		return nil, err
	}
	// Billing is the only writer of the tenant's plan label.
	if err := qTx.SetTenantPlan(ctx, dbgen.SetTenantPlanParams{Plan: tier, TenantID: tenantID}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &Subscription{
		PlanCode: tier, PlanName: planName, Currency: cur, Interval: interval,
		Status: "trialing", CurrentPeriodEnd: &trialEnd, TrialEnd: &trialEnd,
	}, nil
}

// --- billing profile (tax/invoice details) ---

var gstinRe = regexp.MustCompile(`^[0-9A-Z]{15}$`)

// GetBillingProfile returns the tenant's billing and tax details, or an empty
// profile with tax_id_type "none" if none has been saved.
func (s *Service) GetBillingProfile(ctx context.Context, tenantID uuid.UUID) (*BillingProfile, error) {
	row, err := s.q.GetBillingProfile(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &BillingProfile{TaxIDType: "none"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &BillingProfile{
		LegalName:    row.LegalName,
		BillingEmail: row.BillingEmail,
		AddressLine1: row.AddressLine1,
		AddressLine2: row.AddressLine2,
		City:         row.City,
		State:        row.State,
		PostalCode:   row.PostalCode,
		Country:      row.Country,
		TaxIDType:    row.TaxIDType,
		TaxID:        row.TaxID,
	}, nil
}

// UpsertBillingProfile validates and saves the tenant's billing and tax details.
func (s *Service) UpsertBillingProfile(ctx context.Context, tenantID uuid.UUID, p BillingProfile) error {
	if p.TaxIDType == "" {
		p.TaxIDType = "none"
	}
	switch p.TaxIDType {
	case "none":
		p.TaxID = ""
	case "gstin":
		if !gstinRe.MatchString(strings.ToUpper(strings.TrimSpace(p.TaxID))) {
			return errs.ErrBillingTaxIDInvalid.WithMessage("Enter a valid 15-character GSTIN.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	case "vat":
		if strings.TrimSpace(p.TaxID) == "" {
			return errs.ErrBillingTaxIDInvalid.WithMessage("Enter your VAT number.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	default:
		return errs.ErrBillingTaxIDInvalid.WithMessage("Unsupported tax ID type.")
	}
	return s.q.UpsertBillingProfile(ctx, dbgen.UpsertBillingProfileParams{
		TenantID:     tenantID,
		LegalName:    strings.TrimSpace(p.LegalName),
		BillingEmail: strings.TrimSpace(p.BillingEmail),
		AddressLine1: strings.TrimSpace(p.AddressLine1),
		AddressLine2: strings.TrimSpace(p.AddressLine2),
		City:         strings.TrimSpace(p.City),
		State:        strings.TrimSpace(p.State),
		PostalCode:   strings.TrimSpace(p.PostalCode),
		Country:      strings.ToUpper(strings.TrimSpace(p.Country)),
		TaxIDType:    p.TaxIDType,
		TaxID:        p.TaxID,
	})
}

func periodEnd(start time.Time, interval string) time.Time {
	if interval == "year" {
		return start.AddDate(1, 0, 0)
	}
	return start.AddDate(0, 1, 0)
}

// ChangePlan sets or switches the tenant's subscription within tx and issues an
// invoice for the new period. The plan must have a price in currency.
func (s *Service) ChangePlan(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, planCode, currency string) (*Subscription, error) {
	cur, ok := normalizeCurrency(currency)
	if !ok {
		return nil, errs.ErrBillingCurrencyInvalid
	}
	planID, interval, planName, err := s.planByCode(ctx, planCode)
	if err != nil {
		return nil, err
	}
	amt, priced, err := s.priceFor(ctx, planID, cur)
	if err != nil {
		return nil, err
	}
	if !priced {
		return nil, errs.ErrBillingPlanNotPriced
	}

	start := time.Now().UTC()
	end := periodEnd(start, interval)
	qTx := s.q.WithTx(tx)
	if err := qTx.UpsertSubscription(ctx, dbgen.UpsertSubscriptionParams{
		TenantID:    tenantID,
		PlanID:      planID,
		Currency:    cur,
		PeriodStart: start,
		PeriodEnd:   end,
	}); err != nil {
		return nil, err
	}
	// Tax comes from the tenant's billing profile and is zero until a tax
	// configuration is set. amount_minor is the total including tax.
	tr := s.taxFor(ctx, tenantID, amt)
	// Zero-amount plans still get an invoice record.
	if err := qTx.InsertInvoice(ctx, dbgen.InsertInvoiceParams{
		TenantID:           tenantID,
		PlanCode:           planCode,
		Currency:           cur,
		AmountMinor:        tr.TotalMinor,
		PeriodStart:        start,
		PeriodEnd:          end,
		TaxableAmountMinor: tr.TaxableMinor,
		TaxAmountMinor:     tr.TaxMinor,
		TaxRateBps:         int32(tr.RateBps),
		TaxType:            tr.Type,
		PlaceOfSupply:      tr.PlaceOfSupply,
	}); err != nil {
		return nil, err
	}
	// Billing is the only writer of tenants.plan, which holds the tier without
	// the "_year" suffix.
	if err := qTx.SetTenantPlan(ctx, dbgen.SetTenantPlanParams{
		Plan:     strings.TrimSuffix(planCode, "_year"),
		TenantID: tenantID,
	}); err != nil {
		return nil, err
	}
	return &Subscription{
		PlanCode: planCode, PlanName: planName, Currency: cur, AmountMinor: amt,
		Interval: interval, Status: "active",
		CurrentPeriodStart: &start, CurrentPeriodEnd: &end, CancelAtPeriodEnd: false,
	}, nil
}

// Cancel sets the tenant's subscription to end with its current period, within
// tx. It returns errs.ErrBillingNoActiveSubscription if there is no subscription.
func (s *Service) Cancel(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	ct, err := s.q.WithTx(tx).CancelSubscription(ctx, tenantID)
	if err != nil {
		return err
	}
	if ct == 0 {
		return errs.ErrBillingNoActiveSubscription
	}
	return nil
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
	planID, _, planName, err := s.planByCode(ctx, planCode)
	if err != nil {
		return nil, err
	}
	amt, priced, err := s.priceFor(ctx, planID, cur)
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CompleteCheckout(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		// Not a tenant checkout: it may be a signup checkout, whose organization is
		// created now.
		return s.completeSignupCheckout(ctx, id)
	}
	if err != nil {
		return err
	}
	if _, err := s.ChangePlan(ctx, tx, row.TenantID, row.PlanCode, row.Currency); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// completeSignupCheckout claims a pending signup checkout, creates its
// organization and activates the subscription. An unknown or completed checkout
// is a no-op. If creating the organization fails, the checkout returns to
// pending so a retry can try again.
func (s *Service) completeSignupCheckout(ctx context.Context, id uuid.UUID) error {
	if s.orgProvisioner == nil {
		return nil
	}
	var (
		userID                                     uuid.UUID
		name, slug, region, planCode, currencyCode string
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE tenant.signup_checkouts
		SET status = 'completed', completed_at = NOW()
		WHERE id = $1 AND status = 'pending'
		RETURNING user_id, org_name, org_slug, region, plan_code, currency`,
		id,
	).Scan(&userID, &name, &slug, &region, &planCode, &currencyCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // unknown, already completed, or failed — idempotent no-op
	}
	if err != nil {
		return err
	}

	// The tenant's plan label is the tier; the subscription keeps the full code
	// (such as "starter_year") so its interval and price are right.
	tier := strings.TrimSuffix(planCode, "_year")
	// The slug may have been taken since the checkout was staged. Retry with a
	// unique slug: reverting to pending would fail the same way forever, with the
	// customer already charged.
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
		break // other (likely transient) error: fall through and revert for retry
	}
	if provErr != nil {
		_, _ = s.pool.Exec(ctx,
			`UPDATE tenant.signup_checkouts SET status = 'pending', completed_at = NULL WHERE id = $1`, id)
		return provErr
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := s.ChangePlan(ctx, tx, tenantID, planCode, currencyCode); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant.signup_checkouts SET tenant_id = $1 WHERE id = $2`, tenantID, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
	planID, _, planName, err := s.planByCode(ctx, in.PlanCode)
	if err != nil {
		return nil, err
	}
	amt, priced, err := s.priceFor(ctx, planID, cur)
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

// ListInvoices returns the tenant's 100 most recent invoices, newest first.
func (s *Service) ListInvoices(ctx context.Context, tenantID uuid.UUID) ([]Invoice, error) {
	rows, err := s.q.ListInvoices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Invoice, 0, len(rows))
	for _, r := range rows {
		out = append(out, Invoice{
			ID:            r.ID,
			PlanCode:      r.PlanCode,
			Currency:      r.Currency,
			AmountMinor:   r.AmountMinor,
			TaxableMinor:  r.TaxableAmountMinor,
			TaxMinor:      r.TaxAmountMinor,
			TaxRateBps:    int(r.TaxRateBps),
			TaxType:       r.TaxType,
			PlaceOfSupply: r.PlaceOfSupply,
			Status:        r.Status,
			PeriodStart:   r.PeriodStart,
			PeriodEnd:     r.PeriodEnd,
			IssuedAt:      r.IssuedAt,
		})
	}
	return out, nil
}

// --- handlers ---

// Handler serves the billing endpoints.
type Handler struct {
	Service *Service
}

// Mount registers the authenticated billing routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/billing/plans", h.listPlans)
	// A paid plan chosen at signup, before the user has an organization.
	r.Post("/signup/checkout", h.signupCheckout)
	r.Get("/tenants/{tenantID}/billing/subscription", h.getSubscription)
	r.Put("/tenants/{tenantID}/billing/subscription", h.changePlan)
	r.Get("/tenants/{tenantID}/billing/profile", h.getBillingProfile)
	r.Put("/tenants/{tenantID}/billing/profile", h.putBillingProfile)
	r.Post("/tenants/{tenantID}/billing/trial", h.startTrial)
	r.Post("/tenants/{tenantID}/billing/subscription/cancel", h.cancel)
	r.Post("/tenants/{tenantID}/billing/checkout", h.checkout)
	r.Get("/tenants/{tenantID}/billing/invoices", h.listInvoices)
}

// MountPublic registers the payment provider routes. They authenticate by the
// provider's signature rather than a session, so they are public and CSRF-exempt.
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/billing/webhooks/{provider}", h.webhook)
	// The browser posts the signed Razorpay redirect parameters here, because the
	// webhook cannot reach a local server.
	r.Post("/billing/razorpay/verify", h.razorpayVerify)
	// Dev-only sandbox: a mock hosted-checkout page and its pay action, both 404
	// unless the sandbox is enabled.
	r.Get("/billing/sandbox/checkout", h.sandboxCheckoutPage)
	r.Post("/billing/sandbox/pay", h.sandboxPay)
}

// sandboxTmpl renders the dev-only mock hosted-checkout page, labelled as a
// test page, with Pay and Cancel actions.
var sandboxTmpl = template.Must(template.New("sandbox").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sandbox checkout</title>
<style>
body{font-family:system-ui,sans-serif;background:#0b0b0c;color:#e5e5e5;display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center}
.card{background:#161618;border:1px solid #2a2a2e;border-radius:14px;padding:32px;width:360px;box-shadow:0 12px 40px rgba(0,0,0,.4)}
.tag{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#f26d0e;border:1px solid #f26d0e55;border-radius:999px;padding:3px 10px;margin-bottom:18px}
h1{font-size:16px;margin:0 0 4px}.muted{color:#8a8a90;font-size:13px;margin:0 0 20px}
.amount{font-size:34px;font-weight:700;letter-spacing:-.02em;margin:0 0 24px}
button{width:100%;border:0;border-radius:10px;padding:12px;font-size:14px;font-weight:600;cursor:pointer}
.pay{background:#f26d0e;color:#fff;margin-bottom:10px}.cancel{background:transparent;color:#8a8a90;border:1px solid #2a2a2e}
.note{font-size:11px;color:#66666c;margin-top:18px;text-align:center}
</style></head>
<body><div class="card">
<span class="tag">Sandbox · test mode</span>
<h1>{{.Plan}}</h1>
<p class="muted">No real payment is taken.</p>
<p class="amount">{{.Currency}} {{.Amount}}</p>
<form method="POST" action="/v1/billing/sandbox/pay">
  <input type="hidden" name="ref" value="{{.Ref}}">
  <input type="hidden" name="success_url" value="{{.SuccessURL}}">
  <button class="pay" type="submit">Pay {{.Currency}} {{.Amount}}</button>
</form>
<a href="{{.CancelURL}}"><button class="cancel" type="button">Cancel</button></a>
<p class="note">Simulated Stripe/Razorpay hosted checkout for local development.</p>
</div></body></html>`))

type sandboxPageData struct {
	Ref, Plan, Amount, Currency, SuccessURL, CancelURL string
}

// sandboxCheckoutPage renders the mock hosted-checkout page, validating the
// return URLs. It is a 404 when the sandbox is disabled.
func (h *Handler) sandboxCheckoutPage(w http.ResponseWriter, r *http.Request) {
	if !h.Service.SandboxEnabled() {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	q := r.URL.Query()
	successURL, cancelURL := q.Get("success_url"), q.Get("cancel_url")
	if !validReturnURL(successURL) || !validReturnURL(cancelURL) {
		httpx.WriteError(w, r, errs.ErrBillingReturnURLInvalid)
		return
	}
	amt, _ := strconv.ParseInt(q.Get("amount"), 10, 64)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = sandboxTmpl.Execute(w, sandboxPageData{
		Ref:        q.Get("ref"),
		Plan:       q.Get("plan"),
		Amount:     fmt.Sprintf("%.2f", float64(amt)/100),
		Currency:   q.Get("currency"),
		SuccessURL: successURL,
		CancelURL:  cancelURL,
	})
}

// sandboxPay completes the checkout, as a real webhook would, and redirects to
// the success URL. It is a 404 when the sandbox is disabled.
func (h *Handler) sandboxPay(w http.ResponseWriter, r *http.Request) {
	if !h.Service.SandboxEnabled() {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	successURL := r.PostForm.Get("success_url")
	if !validReturnURL(successURL) {
		httpx.WriteError(w, r, errs.ErrBillingReturnURLInvalid)
		return
	}
	if err := h.Service.CompleteCheckout(r.Context(), r.PostForm.Get("ref")); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	http.Redirect(w, r, successURL, http.StatusSeeOther)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBillingTenantInvalid
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrBillingTenantMismatch
	}
	return scope, nil
}

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
}

func (h *Handler) listPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := h.Service.ListPlans(r.Context())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": plans})
}

func (h *Handler) getSubscription(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.GetSubscription(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) startTrial(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode string `json:"plan_code"`
		Currency string `json:"currency"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sub, err := h.Service.StartTrial(r.Context(), tenantID, in.PlanCode, in.Currency)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

func (h *Handler) getBillingProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.GetBillingProfile(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) putBillingProfile(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in BillingProfile
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.UpsertBillingProfile(r.Context(), tenantID, in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.GetBillingProfile(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) changePlan(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode string `json:"plan_code"`
		Currency string `json:"currency"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	sub, err := h.Service.ChangePlan(ctx, tx, tenantID, in.PlanCode, in.Currency)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "billing.plan_changed", ResourceType: "subscription",
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"plan": sub.PlanCode, "currency": sub.Currency, "amount_minor": sub.AmountMinor},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sub)
}

// checkout starts a plan change and returns either a hosted-payment URL or
// {status: "active"} when the plan was activated directly.
func (h *Handler) checkout(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		PlanCode   string `json:"plan_code"`
		Currency   string `json:"currency"`
		Country    string `json:"country"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validReturnURL(in.SuccessURL) || !validReturnURL(in.CancelURL) {
		httpx.WriteError(w, r, errs.ErrBillingCheckoutURLInvalid)
		return
	}
	res, err := h.Service.Checkout(r.Context(), tenantID, in.PlanCode, in.Currency, in.Country, in.SuccessURL, in.CancelURL)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// signupCheckout starts a paid checkout for a plan chosen at signup, before the
// user has an organization, which is created only once the payment completes.
func (h *Handler) signupCheckout(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in struct {
		OrgName    string `json:"org_name"`
		OrgSlug    string `json:"org_slug"`
		Region     string `json:"region"`
		PlanCode   string `json:"plan_code"`
		Currency   string `json:"currency"`
		Country    string `json:"country"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(in.OrgName) == "" || strings.TrimSpace(in.OrgSlug) == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	if !validReturnURL(in.SuccessURL) || !validReturnURL(in.CancelURL) {
		httpx.WriteError(w, r, errs.ErrBillingCheckoutURLInvalid)
		return
	}
	res, err := h.Service.StartSignupCheckout(r.Context(), *p.UserID, SignupCheckoutInput{
		OrgName:    strings.TrimSpace(in.OrgName),
		OrgSlug:    strings.TrimSpace(in.OrgSlug),
		Region:     in.Region,
		PlanCode:   in.PlanCode,
		Currency:   in.Currency,
		Country:    in.Country,
		SuccessURL: in.SuccessURL,
		CancelURL:  in.CancelURL,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// validReturnURL reports whether s is an absolute http or https URL with a host,
// as the success and cancel URLs given to a provider must be.
func validReturnURL(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// webhook receives a provider's payment webhook and completes the checkout of a
// verified successful payment. A no-op still returns 200, so the provider stops
// retrying.
func (h *Handler) webhook(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	sigHeader := h.Service.WebhookSignatureHeader(provider)
	if sigHeader == "" {
		httpx.WriteError(w, r, errs.ErrBillingProviderUnknown)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	if err := h.Service.HandleWebhook(r.Context(), provider, body, r.Header.Get(sigHeader)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// razorpayVerify completes a checkout from a Razorpay payment-link redirect,
// authenticated by the Razorpay signature. It is idempotent with the webhook.
func (h *Handler) razorpayVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PaymentID     string `json:"razorpay_payment_id"`
		PaymentLinkID string `json:"razorpay_payment_link_id"`
		ReferenceID   string `json:"razorpay_payment_link_reference_id"`
		Status        string `json:"razorpay_payment_link_status"`
		Signature     string `json:"razorpay_signature"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
		return
	}
	err := h.Service.CompleteRazorpayCallback(r.Context(), map[string]string{
		"razorpay_payment_id":                in.PaymentID,
		"razorpay_payment_link_id":           in.PaymentLinkID,
		"razorpay_payment_link_reference_id": in.ReferenceID,
		"razorpay_payment_link_status":       in.Status,
		"razorpay_signature":                 in.Signature,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Cancel(ctx, tx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: actorID, ActorType: actorType,
		Action: "billing.subscription_canceled", ResourceType: "subscription",
		IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"cancel_at_period_end": true})
}

func (h *Handler) listInvoices(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.ListInvoices(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
