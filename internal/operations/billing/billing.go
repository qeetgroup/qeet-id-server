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
}

type Invoice struct {
	ID          uuid.UUID `json:"id"`
	PlanCode    string    `json:"plan_code"`
	Currency    string    `json:"currency"`
	AmountMinor int64     `json:"amount_minor"`
	Status      string    `json:"status"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	IssuedAt    time.Time `json:"issued_at"`
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
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPayments wires the card-payment providers.
func (s *Service) SetPayments(p *Payments) { s.payments = p }

// SetAllowUnpaidActivation toggles manual/invoice-only billing (see field doc).
func (s *Service) SetAllowUnpaidActivation(v bool) { s.allowUnpaidActivation = v }

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

// --- seeding ---

type builtinPlan struct {
	code, name, description, interval string
	features                          []string
	sort                              int
	prices                            map[string]int64
}

var builtins = []builtinPlan{
	{
		code: "free", name: "Free", description: "For trying things out.", interval: "month", sort: 1,
		features: []string{"Up to 1,000 monthly active users", "Passkeys, social & password login", "Community support"},
		prices:   map[string]int64{"USD": 0, "EUR": 0, "GBP": 0, "INR": 0, "JPY": 0, "AUD": 0, "CAD": 0},
	},
	{
		code: "starter", name: "Starter", description: "For growing teams.", interval: "month", sort: 2,
		features: []string{"Up to 10,000 MAU", "SAML, SCIM & LDAP", "Audit logs & webhooks", "Email support"},
		prices:   map[string]int64{"USD": 2900, "EUR": 2700, "GBP": 2400, "INR": 240000, "JPY": 4500, "AUD": 4500, "CAD": 3900},
	},
	{
		code: "pro", name: "Pro", description: "For scale and compliance.", interval: "month", sort: 3,
		features: []string{"Up to 100,000 MAU", "Advanced threat protection", "Data-retention controls", "Priority support"},
		prices:   map[string]int64{"USD": 9900, "EUR": 9000, "GBP": 7900, "INR": 800000, "JPY": 15000, "AUD": 15000, "CAD": 13000},
	},
	{
		code: "enterprise", name: "Enterprise", description: "For large orgs with custom needs.", interval: "month", sort: 4,
		features: []string{"Unlimited MAU", "SSO enforcement & directory sync", "SLA, BYOK & data residency", "Dedicated support & onboarding"},
		prices:   map[string]int64{"USD": 29900, "EUR": 27900, "GBP": 24900, "INR": 2490000, "JPY": 45000, "AUD": 45000, "CAD": 39900},
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
		return uuid.Nil, "", "", errs.ErrNotFound.WithDetail("unknown plan")
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
	return &sub, nil
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
		return nil, errs.ErrUnprocessable.WithDetail("currency must be a 3-letter ISO-4217 code")
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
		return nil, errs.ErrUnprocessable.WithDetail("plan " + planCode + " is not priced in " + cur)
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
	// Issue an invoice for the period (zero-amount plans still get a record).
	if err := qTx.InsertInvoice(ctx, dbgen.InsertInvoiceParams{
		TenantID:    tenantID,
		PlanCode:    planCode,
		Currency:    cur,
		AmountMinor: amt,
		PeriodStart: start,
		PeriodEnd:   end,
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
		return errs.ErrNotFound.WithDetail("no active subscription")
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
		return nil, errs.ErrUnprocessable.WithDetail("currency must be a 3-letter ISO-4217 code")
	}
	if country != "" && !countryRe.MatchString(country) {
		return nil, errs.ErrUnprocessable.WithDetail("country must be a 2-letter ISO-3166-1 alpha-2 code")
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
		return nil, errs.ErrUnprocessable.WithDetail("plan " + planCode + " is not priced in " + cur)
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
		return nil, errs.ErrInternal.WithMessage("Couldn't start the payment. Please try again.").WithDetail(err.Error())
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
		return errs.ErrBadRequest.WithDetail("invalid checkout ref")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CompleteCheckout(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already completed, failed, or unknown — idempotent no-op
	}
	if err != nil {
		return err
	}
	if _, err := s.ChangePlan(ctx, tx, row.TenantID, row.PlanCode, row.Currency); err != nil {
		return err
	}
	return tx.Commit(ctx)
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
		return errs.ErrUnauthorized.WithDetail("webhook verification failed")
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

func (s *Service) ListInvoices(ctx context.Context, tenantID uuid.UUID) ([]Invoice, error) {
	rows, err := s.q.ListInvoices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Invoice, 0, len(rows))
	for _, r := range rows {
		out = append(out, Invoice{
			ID:          r.ID,
			PlanCode:    r.PlanCode,
			Currency:    r.Currency,
			AmountMinor: r.AmountMinor,
			Status:      r.Status,
			PeriodStart: r.PeriodStart,
			PeriodEnd:   r.PeriodEnd,
			IssuedAt:    r.IssuedAt,
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
	r.Get("/tenants/{tenantID}/billing/subscription", h.getSubscription)
	r.Put("/tenants/{tenantID}/billing/subscription", h.changePlan)
	r.Post("/tenants/{tenantID}/billing/subscription/cancel", h.cancel)
	r.Post("/tenants/{tenantID}/billing/checkout", h.checkout)
	r.Get("/tenants/{tenantID}/billing/invoices", h.listInvoices)
}

// MountPublic mounts the provider webhook endpoints. They authenticate via the
// provider's signature (not a user session), so they live in the public group
// and are CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/billing/webhooks/{provider}", h.webhook)
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid return URLs"))
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid success_url"))
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
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
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
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("success_url and cancel_url must be absolute http(s) URLs"))
		return
	}
	res, err := h.Service.Checkout(r.Context(), tenantID, in.PlanCode, in.Currency, in.Country, in.SuccessURL, in.CancelURL)
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
		httpx.WriteError(w, r, errs.ErrNotFound.WithDetail("unknown or unconfigured provider"))
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
