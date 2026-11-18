package billing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// PeriodEndInterval is how often RunPeriodEnds runs.
const PeriodEndInterval = 15 * time.Minute

// InvoiceEmailInterval is how often SendInvoiceEmails runs.
const InvoiceEmailInterval = 5 * time.Minute

// PeriodEndRun is what one RunPeriodEnds pass did.
type PeriodEndRun struct {
	Ended, Renewed, PastDue, Failed int
}

// RunPeriodEnds acts on every subscription whose trial or period has ended: a trial or a plan marked
// to cancel moves to free; a free plan starts its next period; a paid plan gets an open renewal invoice
// and is past due until paid, ending once the payment grace runs out. Each change is audited on the
// organization's chain, and running again changes nothing more.
func (s *Service) RunPeriodEnds(ctx context.Context) (PeriodEndRun, error) {
	var run PeriodEndRun
	now := time.Now().UTC()
	due, err := s.q.DueSubscriptions(ctx, dbgen.DueSubscriptionsParams{Now: now, LapsedBefore: now.Add(-s.paymentGrace)})
	if err != nil {
		return run, err
	}
	for _, organizationID := range due {
		step, err := s.endPeriod(ctx, organizationID, now)
		if err != nil {
			run.Failed++
			slog.Warn("billing: period end failed", "organization_id", organizationID, "err", err)
			continue
		}
		switch step {
		case "ended":
			run.Ended++
		case "renewed":
			run.Renewed++
		case "past_due":
			run.PastDue++
		}
	}
	return run, nil
}

// endPeriod takes the organization's subscription one step past the end of its trial
// or period at now, and names the step: "ended", "renewed", "past_due", or ""
// when it was no longer due.
func (s *Service) endPeriod(ctx context.Context, organizationID uuid.UUID, now time.Time) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	sub, err := q.LockSubscription(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	end := sub.CurrentPeriodEnd
	var step string
	switch {
	case sub.Status == "trialing" && sub.TrialEnd != nil && !now.Before(*sub.TrialEnd):
		step, err = "ended", s.endSubscription(ctx, tx, organizationID, sub.Code, "trial_ended")
	case sub.Status == "active" && !now.Before(end) && sub.CancelAtPeriodEnd:
		step, err = "ended", s.endSubscription(ctx, tx, organizationID, sub.Code, "canceled")
	case sub.Status == "active" && !now.Before(end) && sub.AmountMinor == 0:
		// A free plan has nothing to bill. After a long gap it starts afresh
		// from now rather than catching up one period at a time.
		start := end
		if !periodEnd(start, sub.Interval).After(now) {
			start = now
		}
		next := periodEnd(start, sub.Interval)
		if err = q.RenewSubscription(ctx, dbgen.RenewSubscriptionParams{OrganizationID: organizationID, PeriodStart: start, PeriodEnd: next}); err == nil {
			step, err = "renewed", recordBillingEvent(ctx, tx, organizationID, "billing.subscription_renewed",
				map[string]any{"plan_code": sub.Code, "current_period_end": next})
		}
	case sub.Status == "active" && !now.Before(end):
		step, err = "past_due", s.billRenewal(ctx, tx, organizationID, sub)
	case sub.Status == "past_due" && (sub.CancelAtPeriodEnd || !now.Before(end.Add(s.paymentGrace))):
		reason := "unpaid"
		if sub.CancelAtPeriodEnd {
			reason = "canceled"
		}
		step, err = "ended", s.endSubscription(ctx, tx, organizationID, sub.Code, reason)
	default:
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return step, tx.Commit(ctx)
}

// billRenewal issues the open invoice for the period after sub's, taxed by the
// billing profile, and makes the subscription past due until it is paid.
func (s *Service) billRenewal(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, sub dbgen.LockSubscriptionRow) error {
	q := s.q.WithTx(tx)
	start := sub.CurrentPeriodEnd
	next := periodEnd(start, sub.Interval)
	tr := s.taxFor(ctx, q, organizationID, sub.AmountMinor, "")
	invoiceID, err := s.issueInvoice(ctx, q, organizationID, sub.Code, sub.Currency, invoiceKindRenewal, start, next, tr, false)
	if err != nil {
		return err
	}
	if err := q.SetSubscriptionPastDue(ctx, organizationID); err != nil {
		return err
	}
	return recordBillingEvent(ctx, tx, organizationID, "billing.subscription_past_due", map[string]any{
		"plan_code": sub.Code, "invoice_id": invoiceID, "amount_minor": tr.TotalMinor, "currency": sub.Currency,
		"due_at": start.Add(s.paymentGrace),
	})
}

// endSubscription ends the organization's subscription to plan for reason
// ("trial_ended", "canceled" or "unpaid"): the organization moves to free and
// a renewal still open is no longer owed.
func (s *Service) endSubscription(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, plan, reason string) error {
	q := s.q.WithTx(tx)
	if err := q.EndSubscription(ctx, organizationID); err != nil {
		return err
	}
	voided, err := q.VoidOpenRenewals(ctx, organizationID)
	if err != nil {
		return err
	}
	if err := q.SetOrganizationPlan(ctx, dbgen.SetOrganizationPlanParams{Plan: "free", OrganizationID: organizationID}); err != nil {
		return err
	}
	return recordBillingEvent(ctx, tx, organizationID, "billing.subscription_ended", map[string]any{
		"plan_code": plan, "reason": reason, "renewals_voided": voided,
	})
}

// recordBillingEvent audits a change the billing system made itself on the
// organization's chain.
func recordBillingEvent(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, action string, metadata map[string]any) error {
	return audit.Record(ctx, tx, audit.Actor{Type: "system"}.Event(organizationID, action, "subscription", uuid.Nil, metadata))
}

// settleInvoice marks the organization's open invoice paid within tx, by via (a
// provider's name, or "operator") with the payment's reference. A paid renewal
// of a past-due subscription starts the period it billed.
func (s *Service) settleInvoice(ctx context.Context, tx pgx.Tx, organizationID, invoiceID uuid.UUID, reference, via string) error {
	q := s.q.WithTx(tx)
	inv, err := q.LockInvoice(ctx, dbgen.LockInvoiceParams{ID: invoiceID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvoiceNotFound
	}
	if err != nil {
		return err
	}
	if inv.Status != "open" {
		return ErrInvoiceNotOpen
	}
	if err := q.SettleInvoice(ctx, dbgen.SettleInvoiceParams{ID: invoiceID, OrganizationID: organizationID, PaymentReference: reference}); err != nil {
		return err
	}
	if err := recordBillingEvent(ctx, tx, organizationID, "billing.invoice_paid", map[string]any{
		"invoice_id": invoiceID, "invoice_number": inv.InvoiceNumber, "amount_minor": inv.AmountMinor,
		"currency": inv.Currency, "via": via, "reference": reference,
	}); err != nil {
		return err
	}
	if inv.Kind != invoiceKindRenewal {
		return nil
	}
	sub, err := q.LockSubscription(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if sub.Status != "past_due" || !sub.CurrentPeriodEnd.Equal(inv.PeriodStart) {
		return nil
	}
	if err := q.RenewSubscription(ctx, dbgen.RenewSubscriptionParams{
		OrganizationID: organizationID, PeriodStart: inv.PeriodStart, PeriodEnd: inv.PeriodEnd,
	}); err != nil {
		return err
	}
	return recordBillingEvent(ctx, tx, organizationID, "billing.subscription_renewed", map[string]any{
		"plan_code": sub.Code, "invoice_id": invoiceID, "current_period_end": inv.PeriodEnd,
	})
}

// MarkInvoicePaid records, for a platform operator, that an open invoice was
// paid outside a checkout, such as by bank transfer, with the payment's
// reference. It is audited on the organization's chain.
func (s *Service) MarkInvoicePaid(ctx context.Context, invoiceID uuid.UUID, reference string) error {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return errs.ErrBadRequest.WithDetail("a payment reference is required")
	}
	organizationID, err := s.q.InvoiceOrganization(ctx, invoiceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvoiceNotFound
	}
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.settleInvoice(ctx, tx, organizationID, invoiceID, reference, "operator"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PayInvoice opens a hosted checkout for the organization's open invoice, through
// the provider for its billing country or else its currency. Completing it
// settles the invoice; with no provider, it is refused.
func (s *Service) PayInvoice(ctx context.Context, organizationID, invoiceID uuid.UUID, successURL, cancelURL string) (*CheckoutResult, error) {
	inv, err := s.q.LockInvoice(ctx, dbgen.LockInvoiceParams{ID: invoiceID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvoiceNotFound
	}
	if err != nil {
		return nil, err
	}
	if inv.Status != "open" {
		return nil, ErrInvoiceNotOpen
	}
	var provider PaymentProvider
	if p, err := billingProfile(ctx, s.q, organizationID); err == nil && p != nil && p.Country != "" {
		provider = s.payments.forCountry(p.Country)
	} else {
		provider = s.payments.forCurrency(inv.Currency)
	}
	if provider == nil {
		return nil, errs.ErrUnprocessable.
			WithMessage("Online payment isn't available for this invoice. Pay by bank transfer, quoting the invoice number.").
			WithDetail("no card payment provider is configured to charge " + inv.Currency)
	}
	name := "Qeet ID invoice"
	if inv.InvoiceNumber != nil {
		name += " " + *inv.InvoiceNumber
	}
	return s.openCheckout(ctx, provider, dbgen.InsertBillingCheckoutParams{
		OrganizationID:     organizationID,
		Provider:           provider.Name(),
		PlanCode:           inv.PlanCode,
		Currency:           inv.Currency,
		AmountMinor:        inv.AmountMinor,
		TaxableAmountMinor: inv.TaxableAmountMinor,
		TaxAmountMinor:     inv.TaxAmountMinor,
		TaxRateBps:         inv.TaxRateBps,
		TaxType:            inv.TaxType,
		PlaceOfSupply:      inv.PlaceOfSupply,
		InvoiceID:          &invoiceID,
	}, name, successURL, cancelURL)
}

// InvoiceEmails emails each newly issued invoice to the address it was billed
// to, linking to the console at consoleURL.
type InvoiceEmails struct {
	q          *dbgen.Queries
	mailer     notifier.Sender
	consoleURL string
}

// NewInvoiceEmails returns the invoice emails of svc's invoices, sent through
// mailer. It refuses a nil svc or mailer.
func NewInvoiceEmails(svc *Service, mailer notifier.Sender, consoleURL string) (*InvoiceEmails, error) {
	if svc == nil || mailer == nil {
		return nil, errors.New("billing: invoice emails need the billing service and a mailer")
	}
	return &InvoiceEmails{q: svc.q, mailer: mailer, consoleURL: strings.TrimRight(consoleURL, "/")}, nil
}

// Send emails each invoice issued in the last day, and not yet emailed, to
// the billing address it was billed to, and returns how many it sent. Zero
// invoices aren't sent. An invoice whose send fails is tried again on the
// next run.
func (s *InvoiceEmails) Send(ctx context.Context) (int, error) {
	rows, err := s.q.ClaimInvoiceEmails(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, row := range rows {
		var to BillingProfile
		if err := json.Unmarshal(row.BilledTo, &to); err != nil || to.BillingEmail == "" {
			continue
		}
		msg := s.invoiceEmail(row, to.BillingEmail)
		if err := s.mailer.Send(ctx, msg); err != nil {
			slog.Warn("billing: invoice email not sent", "invoice_id", row.ID, "err", err)
			if rerr := s.q.ReleaseInvoiceEmail(ctx, dbgen.ReleaseInvoiceEmailParams{ID: row.ID, OrganizationID: row.OrganizationID}); rerr != nil {
				return sent, rerr
			}
			continue
		}
		sent++
	}
	return sent, nil
}

// invoiceEmail is the message telling to that an invoice was issued.
func (s *InvoiceEmails) invoiceEmail(row dbgen.ClaimInvoiceEmailsRow, to string) notifier.Message {
	number := ""
	if row.InvoiceNumber != nil {
		number = " " + *row.InvoiceNumber
	}
	subject := "Your Qeet ID invoice" + number
	intro := fmt.Sprintf("Here is invoice%s for the %s plan, %s to %s: %s %s.", number, row.PlanCode,
		row.PeriodStart.Format("2 Jan 2006"), row.PeriodEnd.Format("2 Jan 2006"), row.Currency, formatMinor(row.AmountMinor))
	if row.Status == "paid" {
		intro += " It's paid. Thank you."
	} else if row.DueAt != nil {
		intro += " It's due by " + row.DueAt.Format("2 Jan 2006") + "."
	}
	note := "The invoice, with the details it was billed to, is under Settings › Billing in the Qeet ID console."
	if s.consoleURL != "" {
		note += " " + s.consoleURL + "/settings/billing"
	}
	return notifier.Message{
		Channel:        "email",
		To:             to,
		OrganizationID: row.OrganizationID.String(),
		Subject:        subject,
		Body:           intro + " " + note,
		HTML:           emailtmpl.Notice(subject, intro, note),
	}
}

// formatMinor writes an amount in minor units with two decimals.
func formatMinor(minor int64) string {
	sign := ""
	if minor < 0 {
		sign, minor = "-", -minor
	}
	return fmt.Sprintf("%s%d.%02d", sign, minor/100, minor%100)
}

// PaymentMethod is what a checkout was paid with, as its provider reported
// it. Type is "card", "upi", "netbanking", "wallet" or the provider's own
// word; Brand is the card network, bank or wallet.
type PaymentMethod struct {
	Type     string `json:"type"`
	Brand    string `json:"brand,omitempty"`
	Last4    string `json:"last4,omitempty"`
	ExpMonth int    `json:"exp_month,omitempty"`
	ExpYear  int    `json:"exp_year,omitempty"`
}

// SavedPaymentMethod is the payment method of the organization's most recent
// completed checkout. Nothing is kept with the provider: each checkout
// collects its own.
type SavedPaymentMethod struct {
	PaymentMethod
	Provider   string    `json:"provider"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// LastPaymentMethod returns what the organization's latest completed checkout was
// paid with, or nil when no provider has said.
func (s *Service) LastPaymentMethod(ctx context.Context, organizationID uuid.UUID) (*SavedPaymentMethod, error) {
	row, err := s.q.LatestPaymentMethod(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &SavedPaymentMethod{Provider: row.Provider, LastUsedAt: postgres.ZeroIfNull(row.CompletedAt)}
	if err := json.Unmarshal(row.PaymentMethod, &out.PaymentMethod); err != nil {
		return nil, err
	}
	return out, nil
}
