// Package billing is an internal (no external processor) subscription model: a
// platform-managed plan catalogue with per-currency pricing, one subscription
// per tenant, and internally-generated invoices. Money is stored as integer
// minor units plus an ISO-4217 currency code, so any currency is supported.
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

type Plan struct {
	ID          uuid.UUID        `json:"id"`
	Code        string           `json:"code"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Interval    string           `json:"interval"`
	Features    []string         `json:"features"`
	Prices      map[string]int64 `json:"prices"` // currency → minor units
}

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
	// TrialEnd is set while Status == "trialing"; the trial reverts to free after it.
	TrialEnd *time.Time `json:"trial_end"`
}

type Invoice struct {
	ID uuid.UUID `json:"id"`
	// AmountMinor is the total charged (taxable + tax).
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

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	// payments is the optional card-payment provider set (Stripe/Razorpay). nil or
	// empty = no card processing; a paid plan change then needs
	// allowUnpaidActivation or it is refused. Set via SetPayments.
	payments *Payments
	// allowUnpaidActivation enables manual/invoice-only billing: a paid plan with
	// no usable card provider activates directly instead of being refused. OFF by
	// default, so a paid plan is never granted without a real payment.
	allowUnpaidActivation bool
	// orgProvisioner creates the organization behind a *signup* checkout once its
	// payment completes (see StartSignupCheckout). Injected by the composition
	// root so billing doesn't import the identity/tenant package. nil until wired.
	orgProvisioner OrgProvisioner
	// tax is the invoice tax configuration (disabled by default — no tax charged
	// until an operator configures their jurisdiction). Set via SetTaxConfig.
	tax TaxConfig
}

// OrgProvisioner creates an organization (tenant) owned by ownerID. It backs the
// signup-checkout flow, where the org must not exist until the plan is paid for.
// Implemented by identity/tenant and injected via SetOrgProvisioner.
type OrgProvisioner interface {
	ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error)
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPayments wires the card-payment providers.
func (s *Service) SetPayments(p *Payments) { s.payments = p }

// SetAllowUnpaidActivation toggles manual/invoice-only billing (see field doc).
func (s *Service) SetAllowUnpaidActivation(v bool) { s.allowUnpaidActivation = v }

// SetOrgProvisioner wires the organization creator used to complete signup checkouts.
func (s *Service) SetOrgProvisioner(p OrgProvisioner) { s.orgProvisioner = p }

// SetTaxConfig wires invoice tax settings. Zero value (disabled) means no tax.
func (s *Service) SetTaxConfig(c TaxConfig) { s.tax = c }

// SandboxEnabled reports whether the dev-only sandbox payment provider is active.
func (s *Service) SandboxEnabled() bool { return s.payments.SandboxEnabled() }

// CheckoutResult is either an immediately-active subscription (free plan, or a
// paid plan under manual/invoice-only billing) or a hosted-checkout URL to
// redirect the payer to.
type CheckoutResult struct {
	Status      string `json:"status"` // "active" | "checkout"
	CheckoutURL string `json:"checkout_url,omitempty"`
	Provider    string `json:"provider,omitempty"`
}

// SignupCheckoutInput is a paid plan chosen during signup, before any org exists.
// The org is created only when the payment completes.
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

	// Annual variants of the paid self-serve tiers. Same tier + features, billed
	// once a year at 10× the monthly price (two months free ≈ 17% off). The
	// console groups a "<tier>" (month) and its "<tier>_year" plan under one card
	// with a Monthly/Yearly toggle. Free needs no annual plan; Enterprise is
	// contact-sales, so neither has a "_year" variant.
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

// SeedBuiltins upserts the default plan catalogue. Idempotent — safe to run on
// every boot (mirrors rbac.Repository.SeedBuiltins).
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

// StartTrial begins a no-card trial of a paid tier. Eligible only when the
// tenant has no subscription yet (one trial per org); the trial grants the
// tier's entitlements until trial_end, after which it reverts to free unless
// the tenant converts to paid (via Checkout/ChangePlan). No invoice is issued.
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
	// Reflect the trial tier on the tenant label (billing is the sole writer).
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

// GetBillingProfile returns the tenant's billing/tax details, or an empty
// profile (tax_id_type "none") when none has been saved yet.
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

// UpsertBillingProfile validates and persists a tenant's billing/tax details.
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

// ChangePlan sets (or switches) the tenant's subscription and issues an invoice
// for the new period. Validates the plan is priced in the chosen currency.
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
	// Compute tax from the tenant's billing profile (GST/VAT). Disabled by
	// default, so tr is a zero-tax pass-through until an operator configures a
	// jurisdiction. The invoice records the breakdown; amount_minor is the total.
	tr := s.taxFor(ctx, tenantID, amt)
	// Issue an invoice for the period (zero-amount plans still get a record).
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
	// Keep the tenant's plan label in sync with the subscription tier (strip the
	// annual "_year" suffix). Billing is the sole writer of tenants.plan now, so
	// the label stays truthful for anything that reads it (team switcher, admin).
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

// Checkout starts a paid plan change. For a free plan or a currency no card
// provider serves, it activates the subscription immediately (invoice-only,
// the existing behaviour). Otherwise it records a pending checkout and opens a
// hosted payment, returning the URL to redirect the admin to; the provider's
// webhook later completes it via CompleteCheckout. The provider is chosen by
// billing country (config-driven, see Payments.forCountry); an empty country
// falls back to currency-based routing.
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
			provider = s.payments.forCurrency(cur) // legacy fallback when no country given
		}
	}

	// Free plan → nothing to collect, activate directly.
	if amt == 0 {
		return s.activateDirect(ctx, tenantID, planCode, cur)
	}

	// Paid plan but no usable card provider. Never grant a paid plan for free:
	// refuse unless the operator has explicitly opted into manual/invoice-only
	// billing (allowUnpaidActivation).
	if provider == nil {
		if !s.allowUnpaidActivation {
			return nil, errs.ErrUnprocessable.
				WithMessage("Online payment isn't available for this country or currency yet.").
				WithDetail("no card payment provider is configured to charge " + cur + " for the selected billing country")
		}
		return s.activateDirect(ctx, tenantID, planCode, cur)
	}

	// Paid plan with a provider → pending checkout + hosted payment.
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
		return nil, errs.ErrInternalServer.WithMessage("Couldn't start the payment. Please try again.").WithDetail(err.Error())
	}
	_ = s.q.UpdateCheckoutProviderRef(ctx, dbgen.UpdateCheckoutProviderRefParams{
		ProviderRef: providerRef,
		ID:          checkoutID,
	})
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
}

// activateDirect switches the plan in a single transaction without a payment
// step — used for free plans and, when enabled, manual/invoice-only billing.
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

// CompleteCheckout activates the plan behind a paid checkout. It is idempotent:
// the pending→completed transition is claimed atomically, so webhook retries
// (or a duplicate event) activate the subscription exactly once.
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
		// Not a tenant checkout — it may be a signup (pre-tenant) checkout, whose
		// organization is created here, on payment. Unknown refs are a no-op.
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

// completeSignupCheckout finishes a paid signup checkout: it atomically claims
// the pending row, creates the organization (via the injected provisioner), and
// activates its subscription. Idempotent — a webhook retry finds the row already
// completed and no-ops. If provisioning fails after the claim, the row is
// reverted to pending so a retry can try again (CreateWithOwner is atomic, so a
// failure leaves no partial org).
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

	// The org's plan column tracks the tier; the subscription keeps the full code
	// (e.g. "starter_year") so its interval/price are right.
	tier := strings.TrimSuffix(planCode, "_year")
	// The slug can be claimed between staging the checkout and this (post-payment)
	// provisioning. If so, retry with a uniquified slug rather than reverting to
	// pending forever — otherwise the customer is charged but the org never
	// appears (a deterministic failure the webhook would retry endlessly).
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

// StartSignupCheckout opens a hosted payment for a paid plan chosen during
// signup, before any organization exists. The org spec is staged (not created);
// the tenant is created only when the payment completes (completeSignupCheckout),
// so an abandoned payment leaves nothing behind. Free plans must not use this
// path — they create the org directly, with no payment.
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
	// A free plan has nothing to charge; it must go through the direct org-create
	// path, not this one.
	if amt == 0 {
		return nil, errs.ErrBadRequest
	}

	// Fail fast if the slug is already taken, so we never charge for an org we
	// then can't create. (Still re-checked atomically at creation time.)
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
		return nil, errs.ErrInternalServer.WithMessage("Couldn't start the payment. Please try again.").WithDetail(err.Error())
	}
	_, _ = s.pool.Exec(ctx, `UPDATE tenant.signup_checkouts SET provider_ref = $1 WHERE id = $2`, providerRef, checkoutID)
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
}

// HandleWebhook verifies a provider webhook and completes the referenced
// checkout on a successful payment. Non-payment events are acknowledged
// (no-op). An unknown provider returns ErrNotFound; a bad signature ErrUnauthorized.
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

// WebhookSignatureHeader returns the HTTP signature header for a provider, or
// "" if the provider isn't configured.
func (s *Service) WebhookSignatureHeader(providerName string) string {
	if s.payments == nil {
		return ""
	}
	if prov := s.payments.byName(providerName); prov != nil {
		return prov.SignatureHeader()
	}
	return ""
}

// CompleteRazorpayCallback verifies a Razorpay payment-link redirect and, on a
// paid callback, completes the referenced checkout — creating the org behind a
// signup checkout. Idempotent with the webhook, and the path that actually
// completes a checkout in local development (where the async webhook can't reach
// the server).
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

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/billing/plans", h.listPlans)
	// Pre-tenant paid checkout: a user picks a paid plan at signup and the org is
	// created only when the payment completes. User-scoped (no tenant yet).
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

// MountPublic mounts the provider webhook endpoints. They authenticate via the
// provider's signature (not a user session), so they live in the public group
// and are CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/billing/webhooks/{provider}", h.webhook)
	// Razorpay payment-link redirect verification: the browser posts the signed
	// callback params here to complete a checkout, since the async webhook can't
	// reach a local server (idempotent with the webhook). Signature-authenticated.
	r.Post("/billing/razorpay/verify", h.razorpayVerify)
	// Dev-only sandbox provider: a mock hosted-checkout page + its pay action.
	// Both 404 unless the sandbox is enabled (see sandbox handlers).
	r.Get("/billing/sandbox/checkout", h.sandboxCheckoutPage)
	r.Post("/billing/sandbox/pay", h.sandboxPay)
}

// sandboxTmpl renders the dev-only mock hosted-checkout page. It's clearly
// labelled as a test page and offers Pay / Cancel actions only.
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

// sandboxCheckoutPage renders the mock hosted-checkout page. Return URLs are
// validated to avoid an open redirect; 404 when the sandbox is disabled.
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

// sandboxPay completes the referenced checkout (same path a real webhook takes)
// and redirects back to the app's success URL. 404 when the sandbox is disabled.
func (h *Handler) sandboxPay(w http.ResponseWriter, r *http.Request) {
	if !h.Service.SandboxEnabled() {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest)
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

// checkout starts a paid plan change: returns either a hosted-payment URL to
// redirect to, or {status:"active"} when the plan is free / no card provider
// serves the currency (direct activation, the invoice-only path).
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
// user has an organization. The org is created only when the payment completes,
// so an abandoned payment never leaves a dangling org. User-scoped (no tenant).
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

// validReturnURL guards the success/cancel URLs handed to the provider: an
// absolute http(s) URL with a host. (They're the admin app's own origin.)
func validReturnURL(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// webhook receives a provider's payment webhook. The raw body is read for
// signature verification; on a verified successful payment the referenced
// checkout is completed (idempotently). Always returns 200 on a benign no-op so
// the provider doesn't keep retrying acknowledged events.
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

// razorpayVerify completes a checkout from a Razorpay payment-link redirect. The
// browser posts the signed callback params here (the async webhook can't reach a
// local server); completion is idempotent, so a later webhook in production is a
// harmless no-op. Authenticated by the Razorpay signature — CSRF-exempt, in the
// public group.
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
