package billing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// GetSubscription returns the organization's subscription, or one with Status "none"
// if it has none.
func (s *Service) GetSubscription(ctx context.Context, organizationID uuid.UUID) (*Subscription, error) {
	row, err := s.q.GetSubscription(ctx, organizationID)
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
	sub.TrialEnd = row.TrialEnd
	sub.EndedAt = row.EndedAt
	return &sub
}

// Grants reports whether the subscription grants its plan at now: a trial until it ends, a plan marked
// to cancel until its period ends, and any other active or past-due plan for the payment grace beyond
// its period, so a renewal job that hasn't run, or a renewal left unpaid, grants nothing past that.
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

// PlanLabel reads the plan an organization's own record names: the one it is
// on with no subscription.
type PlanLabel func(ctx context.Context, organizationID uuid.UUID) (string, error)

// PlanResolver decides an organization's effective plan, as
// entitlements.PlanResolver asks: its subscription's plan while the
// subscription grants it, free once it lapses, and with no subscription the
// plan its record names (Label), else free. A nil Billing or Label is skipped.
type PlanResolver struct {
	Billing *Service
	Label   PlanLabel
}

// EffectivePlan returns organizationID's effective plan code. A read that
// fails falls through to the next source, and in the end to free.
func (r PlanResolver) EffectivePlan(ctx context.Context, organizationID uuid.UUID) (string, error) {
	if r.Billing != nil {
		if sub, err := r.Billing.GetSubscription(ctx, organizationID); err == nil && sub != nil && sub.PlanCode != "" {
			// A subscription past its paid period or trial, or canceled, grants
			// nothing: the organization is on free, not on the stale label. Evaluated
			// lazily here, with no scheduler.
			if sub.Grants(time.Now()) {
				return sub.PlanCode, nil
			}
			return "free", nil
		}
	}
	if r.Label != nil {
		if plan, err := r.Label(ctx, organizationID); err == nil {
			return plan, nil
		}
	}
	return "free", nil
}

// trialDuration is the length of a no-card trial.
const trialDuration = 14 * 24 * time.Hour

// StartTrial starts a 14-day no-card trial of Starter or Pro for an organization that
// has never had a subscription. The tier's entitlements last until the trial
// ends, then revert to free unless the organization pays. No invoice is issued.
func (s *Service) StartTrial(ctx context.Context, organizationID uuid.UUID, planCode, currency string) (*Subscription, error) {
	tier := strings.TrimSuffix(planCode, "_year")
	if tier != "starter" && tier != "pro" {
		return nil, ErrTrialNotEligible.WithMessage("Trials are available for the Starter and Pro plans.")
	}
	cur, ok := normalizeCurrency(currency)
	if !ok {
		cur = "USD"
	}
	existing, err := s.GetSubscription(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if existing.Status != "none" {
		return nil, ErrTrialNotEligible.WithMessage("This organization isn't eligible for a trial.")
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
		OrganizationID: organizationID,
		PlanID:         planID,
		Currency:       cur,
		TrialEnd:       trialEnd,
	}); err != nil {
		return nil, err
	}
	// Billing is the only writer of the organization's plan label.
	if err := qTx.SetOrganizationPlan(ctx, dbgen.SetOrganizationPlanParams{Plan: tier, OrganizationID: organizationID}); err != nil {
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

// ChangePlan sets or switches the organization's subscription within tx and issues an
// invoice for the new period, taxed by the billing profile. The plan must have
// a price in currency. It takes no payment, so a paid plan's invoice is left
// open; callers check that the plan may be granted unpaid first.
func (s *Service) ChangePlan(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, planCode, currency string) (*Subscription, error) {
	return s.activateUnpaid(ctx, s.q.WithTx(tx), organizationID, planCode, currency, "")
}

// activateUnpaid is ChangePlan through q, taxing by country, the billing
// country of the request, when the profile names none.
func (s *Service) activateUnpaid(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, planCode, currency, country string) (*Subscription, error) {
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return nil, err
	}
	return s.activate(ctx, q, organizationID, p, s.taxFor(ctx, q, organizationID, p.amountMinor, country), false)
}

// activatePaid puts the organization on planCode within tx for a period a completed
// checkout paid for, audited on its chain as the billing system's. The invoice records
// what the checkout charged.
func (s *Service) activatePaid(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, planCode, currency string, charged TaxResult) error {
	q := s.q.WithTx(tx)
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return err
	}
	sub, err := s.activate(ctx, q, organizationID, p, charged, true)
	if err != nil {
		return err
	}
	return recordBillingEvent(ctx, tx, organizationID, "billing.plan_changed", map[string]any{
		"plan": sub.PlanCode, "currency": sub.Currency, "amount_minor": sub.AmountMinor, "via": "checkout",
	})
}

// SwitchPlan is ChangePlan for an organization changing its own plan without a checkout, recorded as
// actor's in the same transaction. A free plan starts a new period; a paid plan that costsNoMore than
// the current one takes over its paid period with no invoice; any other answers
// errs.ErrBillingCheckoutRequired, unless invoice-only billing activates it in that currency.
func (s *Service) SwitchPlan(ctx context.Context, organizationID uuid.UUID, planCode, currency string, actor audit.Actor) (*Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	sub, err := s.switchPlan(ctx, tx, organizationID, planCode, currency)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "billing.plan_changed", "subscription", uuid.Nil,
		map[string]any{"plan": sub.PlanCode, "currency": sub.Currency, "amount_minor": sub.AmountMinor})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sub, nil
}

// switchPlan is SwitchPlan in tx, unrecorded.
func (s *Service) switchPlan(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, planCode, currency string) (*Subscription, error) {
	q := s.q.WithTx(tx)
	p, err := lookupPlanPrice(ctx, q, planCode, currency)
	if err != nil {
		return nil, err
	}
	if p.amountMinor == 0 || s.unpaidActivation(p.currency) {
		return s.activate(ctx, q, organizationID, p, s.taxFor(ctx, q, organizationID, p.amountMinor, ""), false)
	}
	current, err := q.GetSubscription(ctx, organizationID)
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
	if err := q.SwitchSubscriptionPlan(ctx, dbgen.SwitchSubscriptionPlanParams{PlanID: p.id, OrganizationID: organizationID}); err != nil {
		return nil, err
	}
	if err := q.SetOrganizationPlan(ctx, dbgen.SetOrganizationPlanParams{Plan: strings.TrimSuffix(p.code, "_year"), OrganizationID: organizationID}); err != nil {
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

// activate puts the organization on p through q, which must run on a transaction, and
// issues an invoice for the new period charging tr. The invoice is paid when a
// payment was captured, or it charges nothing, and open otherwise. A renewal
// left unpaid is no longer owed once a plan is bought.
func (s *Service) activate(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, p planPrice, tr TaxResult, paid bool) (*Subscription, error) {
	start := time.Now().UTC()
	end := periodEnd(start, p.interval)
	if _, err := q.VoidOpenRenewals(ctx, organizationID); err != nil {
		return nil, err
	}
	if err := q.UpsertSubscription(ctx, dbgen.UpsertSubscriptionParams{
		OrganizationID: organizationID,
		PlanID:         p.id,
		Currency:       p.currency,
		PeriodStart:    start,
		PeriodEnd:      end,
	}); err != nil {
		return nil, err
	}
	if _, err := s.issueInvoice(ctx, q, organizationID, p.code, p.currency, invoiceKindPurchase, start, end, tr, paid); err != nil {
		return nil, err
	}
	// Billing is the only writer of organizations.plan, which holds the tier without
	// the "_year" suffix.
	if err := q.SetOrganizationPlan(ctx, dbgen.SetOrganizationPlanParams{
		Plan:           strings.TrimSuffix(p.code, "_year"),
		OrganizationID: organizationID,
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

// issueInvoice records through q an invoice for plan's period from start to end, charging tr, and
// returns its id: paid when paid is set or nothing is owed, else open and due after the payment grace.
// A charged invoice gets a GST series number and keeps its billing profile, supplier GSTIN and SAC.
func (s *Service) issueInvoice(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID, plan, currency, kind string, start, end time.Time, tr TaxResult, paid bool) (uuid.UUID, error) {
	status := "open"
	due := new(time.Now().UTC().Add(s.paymentGrace))
	if paid || tr.TotalMinor == 0 {
		status, due = "paid", nil
	}
	if kind == invoiceKindRenewal && status == "open" {
		due = new(start.Add(s.paymentGrace))
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
	profile, err := billingProfile(ctx, q, organizationID)
	if err != nil {
		return uuid.Nil, err
	}
	billedTo, err := json.Marshal(profile)
	if err != nil {
		return uuid.Nil, err
	}
	return q.InsertInvoice(ctx, dbgen.InsertInvoiceParams{
		OrganizationID:     organizationID,
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

// CancelAtPeriodEnd is Cancel recorded as actor's, in a transaction of its own.
func (s *Service) CancelAtPeriodEnd(ctx context.Context, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.Cancel(ctx, tx, organizationID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "billing.subscription_canceled", "subscription", uuid.Nil, nil)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Cancel sets the organization's subscription to end with its current period, within
// tx. It returns ErrNoActiveSubscription if there is no subscription.
func (s *Service) Cancel(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID) error {
	ct, err := s.q.WithTx(tx).CancelSubscription(ctx, organizationID)
	if err != nil {
		return err
	}
	if ct == 0 {
		return ErrNoActiveSubscription
	}
	return nil
}

// ListInvoices returns the organization's 100 most recent invoices, newest first.
func (s *Service) ListInvoices(ctx context.Context, organizationID uuid.UUID) ([]Invoice, error) {
	rows, err := s.q.ListInvoices(ctx, organizationID)
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
			DueAt:         r.DueAt,
			PaidAt:        r.PaidAt,
			BilledTo:      billedTo,
			SupplierGSTIN: r.SupplierGstin,
			SAC:           r.Sac,
			EmailedAt:     r.EmailedAt,
		})
	}
	return out, nil
}
