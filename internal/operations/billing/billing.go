// Package billing manages subscriptions: a platform plan catalogue with prices
// per currency, one subscription per tenant, invoices, and hosted card checkouts
// through Stripe, Razorpay or a dev sandbox. Money is integer minor units plus
// an ISO 4217 currency code.
package billing

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
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

// --- seeding ---

// --- plans ---

// --- subscription ---

// --- billing profile (tax/invoice details) ---

// --- handlers ---
