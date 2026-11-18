// Package billing manages subscriptions: a platform plan catalogue with prices
// per currency, one subscription per organization, invoices, and hosted card checkouts
// through Stripe, Razorpay or a dev sandbox. Money is integer minor units plus
// an ISO 4217 currency code.
package billing

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
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

// Subscription is an organization's subscription; Status is "none" if it has none.
// "past_due" is a renewal billed and not yet paid, and "canceled" one that
// ended, at EndedAt. See Grants for how long each grants its plan.
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
	EndedAt            *time.Time `json:"ended_at"`

	grace time.Duration // how long a renewal may go unpaid
}

// Invoice is an issued invoice. AmountMinor is TaxableMinor plus TaxMinor. Status is "paid" once
// captured or when nothing is owed, "open" until then (due at DueAt), or "void" for a renewal no longer
// owed. Kind is "purchase" or "renewal". Number is the GST invoice number (nil on a zero invoice);
// BilledTo is the billing profile when it was issued.
type Invoice struct {
	ID            uuid.UUID `json:"id"`
	Number        *string   `json:"invoice_number"`
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

	Kind          string          `json:"kind"`
	DueAt         *time.Time      `json:"due_at"`
	PaidAt        *time.Time      `json:"paid_at"`
	BilledTo      *BillingProfile `json:"billed_to"`
	SupplierGSTIN string          `json:"supplier_gstin"`
	SAC           string          `json:"sac"`
	EmailedAt     *time.Time      `json:"emailed_at"`
}

// BillingProfile is an organization's billing & tax details, carried onto invoices.
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
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries

	payments              *Payments      // card providers
	allowUnpaidActivation bool           // invoice-only billing
	orgProvisioner        OrgProvisioner // creates a signup checkout's organization
	tax                   TaxConfig      // invoice tax; the zero value charges none
	paymentGrace          time.Duration  // how long an open invoice may go unpaid
}

// Config is how a Service bills. Payments and OrgProvisioner are required; a
// non-positive PaymentGrace is DefaultPaymentGrace.
type Config struct {
	Payments              *Payments      // card providers: NewPayments with no keys charges no card
	AllowUnpaidActivation bool           // invoice-only billing: Checkout activates a paid plan no card provider can charge
	OrgProvisioner        OrgProvisioner // creates the organization a signup checkout pays for
	Tax                   TaxConfig      // invoice tax; the zero value charges none
	PaymentGrace          time.Duration  // how long an open invoice may go unpaid: a renewal's plan lapses that long after its period ends
}

// OrgProvisioner creates an organization owned by ownerID. It completes
// a signup checkout, whose organization must not exist until the plan is paid.
type OrgProvisioner interface {
	ProvisionOrg(ctx context.Context, ownerID uuid.UUID, name, slug, region, plan string) (uuid.UUID, error)
}

// DefaultPaymentGrace is how long an open invoice may go unpaid by default.
const DefaultPaymentGrace = 7 * 24 * time.Hour

// NewService returns a Service billing as c says. It refuses a Config without
// Payments or an OrgProvisioner.
func NewService(pool *pgxpool.Pool, c Config) (*Service, error) {
	switch {
	case c.Payments == nil:
		return nil, errors.New("billing: the payment providers are required (NewPayments charges no card without keys)")
	case c.OrgProvisioner == nil:
		return nil, errors.New("billing: an organization provisioner is required to complete signup checkouts")
	}
	grace := c.PaymentGrace
	if grace <= 0 {
		grace = DefaultPaymentGrace
	}
	return &Service{pool: pool, q: dbgen.New(pool), payments: c.Payments, allowUnpaidActivation: c.AllowUnpaidActivation,
		orgProvisioner: c.OrgProvisioner, tax: c.Tax, paymentGrace: grace}, nil
}

// Pool returns the service's database pool.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SandboxEnabled reports whether the dev-only sandbox payment provider is active.
func (s *Service) SandboxEnabled() bool { return s.payments.SandboxEnabled() }

// --- seeding ---

// --- plans ---

// --- subscription ---

// --- billing profile (tax/invoice details) ---

// --- handlers ---
