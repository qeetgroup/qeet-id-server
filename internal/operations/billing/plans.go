package billing

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
			Sort:        int32(b.sort), // #nosec G115 -- built-in plan order, 1–6
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

// planByCode returns the id, interval and name of the active plan with code,
// read through q.
func planByCode(ctx context.Context, q *dbgen.Queries, code string) (uuid.UUID, string, string, error) {
	row, err := q.GetBillingPlanByCode(ctx, code)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", "", errs.ErrBillingPlanNotFound
	}
	if err != nil {
		return uuid.Nil, "", "", err
	}
	return row.ID, row.Interval, row.Name, nil
}

// priceFor returns the plan's price in currency, read through q, and whether it
// has one.
func priceFor(ctx context.Context, q *dbgen.Queries, planID uuid.UUID, currency string) (int64, bool, error) {
	amt, err := q.GetBillingPlanPrice(ctx, dbgen.GetBillingPlanPriceParams{
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

// planPrice is a plan and its price in one currency.
type planPrice struct {
	id                   uuid.UUID
	code, name, interval string
	currency             string
	amountMinor          int64
}

// lookupPlanPrice returns the plan with code and its price in currency, read
// through q. The plan must exist and have a price in currency.
func lookupPlanPrice(ctx context.Context, q *dbgen.Queries, code, currency string) (planPrice, error) {
	cur, ok := normalizeCurrency(currency)
	if !ok {
		return planPrice{}, errs.ErrBillingCurrencyInvalid
	}
	id, interval, name, err := planByCode(ctx, q, code)
	if err != nil {
		return planPrice{}, err
	}
	amt, priced, err := priceFor(ctx, q, id, cur)
	if err != nil {
		return planPrice{}, err
	}
	if !priced {
		return planPrice{}, errs.ErrBillingPlanNotPriced
	}
	return planPrice{id: id, code: code, name: name, interval: interval, currency: cur, amountMinor: amt}, nil
}
