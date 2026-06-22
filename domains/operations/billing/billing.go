// Package billing is an internal (no external processor) subscription model:
// a platform-managed plan catalogue with per-currency pricing, one subscription
// per tenant in a chosen currency, and internally-generated invoices.
//
// Money is stored as integer minor units (cents/pence/sen/…) plus an ISO-4217
// currency code; the number of fraction digits is applied at display time, so
// any currency is supported. Plans can be priced in any set of currencies; a
// tenant may only subscribe in a currency the chosen plan is priced in.
package billing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

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
	// payments is the optional card-payment provider set (Stripe/Razorpay). nil
	// or empty = invoice-only: a paid plan change activates directly. Set via
	// SetPayments.
	payments *Payments
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// SetPayments wires the card-payment providers. Called from cmd/server/main.go.
func (s *Service) SetPayments(p *Payments) { s.payments = p }

// CheckoutResult is either an immediately-active subscription (free plan or no
// card provider for the currency) or a hosted-checkout URL to redirect to.
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
		var planID uuid.UUID
		if err := s.pool.QueryRow(ctx, `
			INSERT INTO platform.billing_plans (code, name, description, interval, features, sort)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (code) DO UPDATE SET
				name = EXCLUDED.name, description = EXCLUDED.description,
				interval = EXCLUDED.interval, features = EXCLUDED.features, sort = EXCLUDED.sort
			RETURNING id
		`, b.code, b.name, b.description, b.interval, feat, b.sort).Scan(&planID); err != nil {
			return err
		}
		for cur, amt := range b.prices {
			if _, err := s.pool.Exec(ctx, `
				INSERT INTO platform.billing_plan_prices (plan_id, currency, amount_minor)
				VALUES ($1, $2, $3)
				ON CONFLICT (plan_id, currency) DO UPDATE SET amount_minor = EXCLUDED.amount_minor
			`, planID, cur, amt); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- plans ---

func (s *Service) ListPlans(ctx context.Context) ([]Plan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, code, name, description, interval, features
		FROM platform.billing_plans WHERE active = TRUE ORDER BY sort, name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := []Plan{}
	byID := map[uuid.UUID]int{}
	for rows.Next() {
		var p Plan
		var feat []byte
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Description, &p.Interval, &feat); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(feat, &p.Features)
		if p.Features == nil {
			p.Features = []string{}
		}
		p.Prices = map[string]int64{}
		byID[p.ID] = len(plans)
		plans = append(plans, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	priceRows, err := s.pool.Query(ctx, `SELECT plan_id, currency, amount_minor FROM platform.billing_plan_prices`)
	if err != nil {
		return nil, err
	}
	defer priceRows.Close()
	for priceRows.Next() {
		var pid uuid.UUID
		var cur string
		var amt int64
		if err := priceRows.Scan(&pid, &cur, &amt); err != nil {
			return nil, err
		}
		if idx, ok := byID[pid]; ok {
			plans[idx].Prices[cur] = amt
		}
	}
	return plans, priceRows.Err()
}

func (s *Service) planByCode(ctx context.Context, code string) (uuid.UUID, string, string, error) {
	var id uuid.UUID
	var interval, name string
	err := s.pool.QueryRow(ctx, `SELECT id, interval, name FROM platform.billing_plans WHERE code = $1 AND active = TRUE`, code).Scan(&id, &interval, &name)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", "", errs.ErrNotFound.WithDetail("unknown plan")
	}
	return id, interval, name, err
}

func (s *Service) priceFor(ctx context.Context, planID uuid.UUID, currency string) (int64, bool, error) {
	var amt int64
	err := s.pool.QueryRow(ctx, `SELECT amount_minor FROM platform.billing_plan_prices WHERE plan_id = $1 AND currency = $2`, planID, currency).Scan(&amt)
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
	var sub Subscription
	var start, end time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT p.code, p.name, p.interval, s.currency, s.status,
		       s.current_period_start, s.current_period_end, s.cancel_at_period_end,
		       COALESCE(pp.amount_minor, 0)
		FROM tenant.subscriptions s
		JOIN platform.billing_plans p ON p.id = s.plan_id
		LEFT JOIN platform.billing_plan_prices pp ON pp.plan_id = s.plan_id AND pp.currency = s.currency
		WHERE s.tenant_id = $1
	`, tenantID).Scan(&sub.PlanCode, &sub.PlanName, &sub.Interval, &sub.Currency, &sub.Status,
		&start, &end, &sub.CancelAtPeriodEnd, &sub.AmountMinor)
	if errors.Is(err, pgx.ErrNoRows) {
		return &Subscription{Status: "none"}, nil
	}
	if err != nil {
		return nil, err
	}
	sub.CurrentPeriodStart = &start
	sub.CurrentPeriodEnd = &end
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
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant.subscriptions
			(tenant_id, plan_id, currency, status, current_period_start, current_period_end, cancel_at_period_end, updated_at)
		VALUES ($1, $2, $3, 'active', $4, $5, FALSE, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			plan_id = EXCLUDED.plan_id, currency = EXCLUDED.currency, status = 'active',
			current_period_start = EXCLUDED.current_period_start,
			current_period_end = EXCLUDED.current_period_end,
			cancel_at_period_end = FALSE, updated_at = NOW()
	`, tenantID, planID, cur, start, end); err != nil {
		return nil, err
	}
	// Issue an invoice for the period (zero-amount plans still get a record).
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant.invoices (tenant_id, plan_code, currency, amount_minor, status, period_start, period_end)
		VALUES ($1, $2, $3, $4, 'paid', $5, $6)
	`, tenantID, planCode, cur, amt, start, end); err != nil {
		return nil, err
	}
	return &Subscription{
		PlanCode: planCode, PlanName: planName, Currency: cur, AmountMinor: amt,
		Interval: interval, Status: "active",
		CurrentPeriodStart: &start, CurrentPeriodEnd: &end, CancelAtPeriodEnd: false,
	}, nil
}

func (s *Service) Cancel(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	ct, err := tx.Exec(ctx, `
		UPDATE tenant.subscriptions SET cancel_at_period_end = TRUE, updated_at = NOW() WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound.WithDetail("no active subscription")
	}
	return nil
}

// Checkout starts a paid plan change. For a free plan or a currency no card
// provider serves, it activates the subscription immediately (invoice-only,
// the existing behaviour). Otherwise it records a pending checkout and opens a
// hosted payment, returning the URL to redirect the admin to; the provider's
// webhook later completes it via CompleteCheckout.
func (s *Service) Checkout(ctx context.Context, tenantID uuid.UUID, planCode, currency, successURL, cancelURL string) (*CheckoutResult, error) {
	cur, ok := normalizeCurrency(currency)
	if !ok {
		return nil, errs.ErrUnprocessable.WithDetail("currency must be a 3-letter ISO-4217 code")
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
		provider = s.payments.forCurrency(cur)
	}
	// Free plan, or no card provider for this currency → activate directly.
	if amt == 0 || provider == nil {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback(ctx)
		if _, err := s.ChangePlan(ctx, tx, tenantID, planCode, cur); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &CheckoutResult{Status: "active"}, nil
	}

	// Paid plan with a provider → pending checkout + hosted payment.
	var checkoutID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO tenant.billing_checkouts (tenant_id, provider, plan_code, currency, amount_minor)
		VALUES ($1, $2, $3, $4, $5) RETURNING id
	`, tenantID, provider.Name(), planCode, cur, amt).Scan(&checkoutID); err != nil {
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
		_, _ = s.pool.Exec(ctx, `UPDATE tenant.billing_checkouts SET status = 'failed' WHERE id = $1`, checkoutID)
		return nil, errs.ErrInternal.WithMessage("Couldn't start the payment. Please try again.").WithDetail(err.Error())
	}
	_, _ = s.pool.Exec(ctx, `UPDATE tenant.billing_checkouts SET provider_ref = $2 WHERE id = $1`, checkoutID, providerRef)
	return &CheckoutResult{Status: "checkout", CheckoutURL: redirectURL, Provider: provider.Name()}, nil
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
	var tenantID uuid.UUID
	var planCode, currency string
	err = tx.QueryRow(ctx, `
		UPDATE tenant.billing_checkouts SET status = 'completed', completed_at = NOW()
		WHERE id = $1 AND status = 'pending'
		RETURNING tenant_id, plan_code, currency
	`, id).Scan(&tenantID, &planCode, &currency)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already completed, failed, or unknown — idempotent no-op
	}
	if err != nil {
		return err
	}
	if _, err := s.ChangePlan(ctx, tx, tenantID, planCode, currency); err != nil {
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
	rows, err := s.pool.Query(ctx, `
		SELECT id, plan_code, currency, amount_minor, status, period_start, period_end, issued_at
		FROM tenant.invoices WHERE tenant_id = $1 ORDER BY issued_at DESC LIMIT 100
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Invoice{}
	for rows.Next() {
		var inv Invoice
		if err := rows.Scan(&inv.ID, &inv.PlanCode, &inv.Currency, &inv.AmountMinor, &inv.Status, &inv.PeriodStart, &inv.PeriodEnd, &inv.IssuedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
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
	res, err := h.Service.Checkout(r.Context(), tenantID, in.PlanCode, in.Currency, in.SuccessURL, in.CancelURL)
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
