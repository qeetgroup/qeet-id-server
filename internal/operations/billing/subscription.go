package billing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
	sub := subscriptionFromRow(row)
	sub.grace = s.paymentGrace
	return sub, nil
}

// subscriptionFromRow converts a GetSubscription row.
func subscriptionFromRow(row dbgen.GetSubscriptionRow) *Subscription {
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
	sub.TrialEnd = timePtr(row.TrialEnd)
	sub.EndedAt = timePtr(row.EndedAt)
	return &sub
}

// Grants reports whether the subscription grants its plan at now. A trial
// grants until it ends, and a plan marked to cancel until its period ends.
// Any other active or past-due plan grants for the payment grace beyond its
// period, while its renewal is billed and paid, so a renewal job that hasn't
// run, or a renewal left unpaid, grants nothing past that.
func (s *Subscription) Grants(now time.Time) bool {
	switch s.Status {
	case "active", "past_due":
		if s.CurrentPeriodEnd == nil {
			return false
		}
		end := *s.CurrentPeriodEnd
		if !s.CancelAtPeriodEnd {
			end = end.Add(s.grace)
		}
		return now.Before(end)
	case "trialing":
		return s.TrialEnd != nil && now.Before(*s.TrialEnd)
	default:
		return false
	}
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
	planID, interval, planName, err := planByCode(ctx, s.q, tier)
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

func periodEnd(start time.Time, interval string) time.Time {
	if interval == "year" {
		return start.AddDate(1, 0, 0)
	}
	return start.AddDate(0, 1, 0)
}

// ChangePlan sets or switches the tenant's subscription within tx and issues an
// invoice for the new period, taxed by the billing profile. The plan must have
// a price in currency. It takes no payment, so a paid plan's invoice is left
// open; callers check that the plan may be granted unpaid first.
func (s *Service) ChangePlan(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, planCode, currency string) (*Subscription, error) {
	return s.activateUnpaid(ctx, s.q.WithTx(tx), tenantID, planCode, currency, "")
}

// activateUnpaid is ChangePlan through q, taxing by country, the billing
// country of the request, when the profile names none.
func (s *Service) activateUnpaid(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, planCode, currency, country string) (*Subscription, error) {
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return nil, err
	}
	return s.activate(ctx, q, tenantID, p, s.taxFor(ctx, q, tenantID, p.amountMinor, country), false)
}

// activatePaid puts the tenant on planCode within tx for a period a completed
// checkout paid for. The invoice records what the checkout charged.
func (s *Service) activatePaid(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, planCode, currency string, charged TaxResult) error {
	q := s.q.WithTx(tx)
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return err
	}
	_, err = s.activate(ctx, q, tenantID, p, charged, true)
	return err
}

// SwitchPlan is ChangePlan for a tenant changing its own plan without a
// checkout. A free plan starts a new period. A paid plan that costsNoMore than
// the current subscription takes over its paid period, with no new invoice;
// any other returns errs.ErrBillingCheckoutRequired, unless invoice-only
// billing activates the plan in that currency.
func (s *Service) SwitchPlan(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, planCode, currency string) (*Subscription, error) {
	q := s.q.WithTx(tx)
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return nil, err
	}
	if p.amountMinor == 0 || s.unpaidActivation(p.currency) {
		return s.activate(ctx, q, tenantID, p, s.taxFor(ctx, q, tenantID, p.amountMinor, ""), false)
	}
	current, err := q.GetSubscription(ctx, tenantID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// With no subscription, current is empty and pays for nothing.
	if !costsNoMore(p, current) {
		return nil, errs.ErrBillingCheckoutRequired.
			WithMessage("This plan costs more than your current one. Start a checkout to switch to it.")
	}
	if current.Code == p.code {
		sub := subscriptionFromRow(current)
		sub.grace = s.paymentGrace
		return sub, nil
	}
	if err := q.SwitchSubscriptionPlan(ctx, dbgen.SwitchSubscriptionPlanParams{PlanID: p.id, TenantID: tenantID}); err != nil {
		return nil, err
	}
	if err := q.SetTenantPlan(ctx, dbgen.SetTenantPlanParams{Plan: strings.TrimSuffix(p.code, "_year"), TenantID: tenantID}); err != nil {
		return nil, err
	}
	sub := subscriptionFromRow(current)
	sub.PlanCode, sub.PlanName, sub.AmountMinor, sub.CancelAtPeriodEnd = p.code, p.name, p.amountMinor, false
	sub.grace = s.paymentGrace
	return sub, nil
}

// costsNoMore reports whether the current subscription already pays for p: it
// is active, not a trial, with its paid period still running, in p's currency
// and interval, and its plan is priced at least as high as p. Prices in another
// currency or interval don't compare.
func costsNoMore(p planPrice, current dbgen.GetSubscriptionRow) bool {
	return current.Status == "active" &&
		time.Now().Before(current.CurrentPeriodEnd) &&
		current.Currency == p.currency &&
		current.Interval == p.interval &&
		p.amountMinor <= current.AmountMinor
}

// unpaidActivation reports whether invoice-only billing activates a paid plan in
// currency without payment: it is enabled and no card provider charges currency.
func (s *Service) unpaidActivation(currency string) bool {
	return s.allowUnpaidActivation && s.payments.forCurrency(currency) == nil
}

// activate puts the tenant on p through q, which must run on a transaction, and
// issues an invoice for the new period charging tr. The invoice is paid when a
// payment was captured, or it charges nothing, and open otherwise. A renewal
// left unpaid is no longer owed once a plan is bought.
func (s *Service) activate(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, p planPrice, tr TaxResult, paid bool) (*Subscription, error) {
	start := time.Now().UTC()
	end := periodEnd(start, p.interval)
	if _, err := q.VoidOpenRenewals(ctx, tenantID); err != nil {
		return nil, err
	}
	if err := q.UpsertSubscription(ctx, dbgen.UpsertSubscriptionParams{
		TenantID:    tenantID,
		PlanID:      p.id,
		Currency:    p.currency,
		PeriodStart: start,
		PeriodEnd:   end,
	}); err != nil {
		return nil, err
	}
	if _, err := s.issueInvoice(ctx, q, tenantID, p.code, p.currency, invoiceKindPurchase, start, end, tr, paid); err != nil {
		return nil, err
	}
	// Billing is the only writer of tenants.plan, which holds the tier without
	// the "_year" suffix.
	if err := q.SetTenantPlan(ctx, dbgen.SetTenantPlanParams{
		Plan:     strings.TrimSuffix(p.code, "_year"),
		TenantID: tenantID,
	}); err != nil {
		return nil, err
	}
	return &Subscription{
		PlanCode: p.code, PlanName: p.name, Currency: p.currency, AmountMinor: p.amountMinor,
		Interval: p.interval, Status: "active",
		CurrentPeriodStart: &start, CurrentPeriodEnd: &end, CancelAtPeriodEnd: false,
		grace: s.paymentGrace,
	}, nil
}

// Invoice kinds.
const (
	invoiceKindPurchase = "purchase" // a plan bought or changed
	invoiceKindRenewal  = "renewal"  // the next period of a plan, billed at its end
)

// issueInvoice records an invoice through q for plan's period from start to
// end, charging tr, and returns its id. It is paid when paid is set or nothing
// is owed, and otherwise open, due after the payment grace. It numbers a
// charged invoice in the GST series and keeps the billing profile it was
// issued to, with the supplier's GSTIN and SAC.
func (s *Service) issueInvoice(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, plan, currency, kind string, start, end time.Time, tr TaxResult, paid bool) (uuid.UUID, error) {
	status := "open"
	due := pgtype.Timestamptz{Time: time.Now().UTC().Add(s.paymentGrace), Valid: true}
	if paid || tr.TotalMinor == 0 {
		status, due = "paid", pgtype.Timestamptz{}
	}
	if kind == invoiceKindRenewal && status == "open" {
		due.Time = start.Add(s.paymentGrace)
	}
	// Zero-amount plans still get an invoice record, without a number.
	var number *string
	if tr.TotalMinor > 0 {
		fy := financialYear(time.Now().UTC())
		n, err := q.NextInvoiceNumber(ctx, fy)
		if err != nil {
			return uuid.Nil, err
		}
		v := invoiceNumber(fy, n)
		number = &v
	}
	profile, err := billingProfile(ctx, q, tenantID)
	if err != nil {
		return uuid.Nil, err
	}
	billedTo, err := json.Marshal(profile)
	if err != nil {
		return uuid.Nil, err
	}
	return q.InsertInvoice(ctx, dbgen.InsertInvoiceParams{
		TenantID:           tenantID,
		PlanCode:           plan,
		Currency:           currency,
		AmountMinor:        tr.TotalMinor,
		Status:             status,
		InvoiceNumber:      number,
		PeriodStart:        start,
		PeriodEnd:          end,
		TaxableAmountMinor: tr.TaxableMinor,
		TaxAmountMinor:     tr.TaxMinor,
		TaxRateBps:         int32(tr.RateBps), // #nosec G115 -- operator-set GST rate in basis points
		TaxType:            tr.Type,
		PlaceOfSupply:      tr.PlaceOfSupply,
		Kind:               kind,
		DueAt:              due,
		BilledTo:           billedTo,
		SupplierGstin:      s.tax.SupplierGSTIN,
		Sac:                s.tax.SAC,
	})
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

// ListInvoices returns the tenant's 100 most recent invoices, newest first.
func (s *Service) ListInvoices(ctx context.Context, tenantID uuid.UUID) ([]Invoice, error) {
	rows, err := s.q.ListInvoices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Invoice, 0, len(rows))
	for _, r := range rows {
		var billedTo *BillingProfile
		if len(r.BilledTo) > 0 {
			billedTo = &BillingProfile{}
			if err := json.Unmarshal(r.BilledTo, billedTo); err != nil {
				return nil, err
			}
		}
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
			Number:        r.InvoiceNumber,
			PeriodStart:   r.PeriodStart,
			PeriodEnd:     r.PeriodEnd,
			IssuedAt:      r.IssuedAt,
			Kind:          r.Kind,
			DueAt:         timePtr(r.DueAt),
			PaidAt:        timePtr(r.PaidAt),
			BilledTo:      billedTo,
			SupplierGSTIN: r.SupplierGstin,
			SAC:           r.Sac,
			EmailedAt:     timePtr(r.EmailedAt),
		})
	}
	return out, nil
}

// timePtr is t, or nil when it is NULL.
func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}
