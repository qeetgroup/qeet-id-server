//go:build integration

package billing

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// endPeriodAgo moves the tenant's period, or trial, to have ended ago.
func endPeriodAgo(t *testing.T, tenant uuid.UUID, ago time.Duration) {
	t.Helper()
	end := time.Now().UTC().Add(-ago)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		UPDATE tenant.subscriptions
		SET current_period_start = $2::timestamptz - interval '1 month', current_period_end = $2,
		    trial_end = CASE WHEN trial_end IS NULL THEN NULL ELSE $2 END
		WHERE tenant_id = $1`, tenant, end); err != nil {
		t.Fatal(err)
	}
}

// runPeriodEnds runs the period-end job once.
func runPeriodEnds(t *testing.T, svc *Service) PeriodEndRun {
	t.Helper()
	run, err := svc.RunPeriodEnds(dbtest.Context(t))
	if err != nil || run.Failed > 0 {
		t.Fatalf("period ends: %+v, %v", run, err)
	}
	return run
}

// tenantPlan is the tenant's plan label.
func tenantPlan(t *testing.T, tenant uuid.UUID) string {
	t.Helper()
	var plan string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT plan FROM tenant.tenants WHERE id = $1`, tenant).Scan(&plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

// events counts the tenant's audit events of action with the reason given
// ("" for any).
func events(t *testing.T, tenant uuid.UUID, action, reason string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2
		AND actor_type = 'system' AND ($3 = '' OR metadata->>'reason' = $3)`, tenant, action, reason)
}

// TestSubscriptionsEndAtTheirPeriodEnd checks that a plan marked to cancel,
// and a trial, end when their period does and move the organisation to free,
// once however often the job runs, and that a free plan starts its next
// period.
func TestSubscriptionsEndAtTheirPeriodEnd(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	canceled, trial, free, bystander := dbtest.Tenant(t), dbtest.Tenant(t), dbtest.Tenant(t), dbtest.Tenant(t)
	subscribe(t, svc, canceled, "pro", "USD")
	cancelSubscription(t, svc, canceled)
	if _, err := svc.StartTrial(ctx, trial, "pro", "USD"); err != nil {
		t.Fatal(err)
	}
	subscribe(t, svc, free, "free", "USD")
	subscribe(t, svc, bystander, "pro", "USD")
	for _, tenant := range []uuid.UUID{canceled, trial, free} {
		endPeriodAgo(t, tenant, time.Minute)
	}

	runPeriodEnds(t, svc)
	runPeriodEnds(t, svc)

	for tenant, reason := range map[uuid.UUID]string{canceled: "canceled", trial: "trial_ended"} {
		sub, err := svc.GetSubscription(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if sub.Status != "canceled" || sub.EndedAt == nil || sub.Grants(time.Now()) || tenantPlan(t, tenant) != "free" {
			t.Errorf("%s subscription after its end: %+v, plan %s; want canceled, ended and free", reason, sub, tenantPlan(t, tenant))
		}
		if n := events(t, tenant, "billing.subscription_ended", reason); n != 1 {
			t.Errorf("%s: %d billing.subscription_ended events, want one", reason, n)
		}
	}
	sub, err := svc.GetSubscription(ctx, free)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "active" || !sub.CurrentPeriodEnd.After(time.Now()) || events(t, free, "billing.subscription_renewed", "") != 1 {
		t.Errorf("free plan after its period: %+v, want active for a new period, renewed once", sub)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action LIKE 'billing.subscription_%'`, bystander); n != 0 {
		t.Errorf("an organisation whose period runs on has %d subscription events", n)
	}
	if sub, _ := svc.GetSubscription(ctx, bystander); sub.Status != "active" {
		t.Errorf("an organisation whose period runs on is %s", sub.Status)
	}
}

// TestRenewalsAreBilledAndLapseUnpaid checks that a paid plan's period end
// bills the next period with an open renewal invoice, due after the grace,
// that paying it renews the plan, and that one left unpaid past the grace
// ends the subscription and is no longer owed.
func TestRenewalsAreBilledAndLapseUnpaid(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	paid, unpaid := dbtest.Tenant(t), dbtest.Tenant(t)
	for _, tenant := range []uuid.UUID{paid, unpaid} {
		subscribe(t, svc, tenant, "pro", "USD")
		endPeriodAgo(t, tenant, time.Minute)
	}
	if run := runPeriodEnds(t, svc); run.PastDue != 2 {
		t.Fatalf("period ends %+v, want two renewals billed", run)
	}
	runPeriodEnds(t, svc)

	before, err := svc.GetSubscription(ctx, paid)
	if err != nil {
		t.Fatal(err)
	}
	renewal := latestInvoice(t, svc, paid)
	if before.Status != "past_due" || !before.Grants(time.Now()) {
		t.Errorf("subscription with its renewal billed: %+v, want past due and still granted", before)
	}
	if renewal.Kind != invoiceKindRenewal || renewal.Status != "open" || renewal.DueAt == nil ||
		!renewal.PeriodStart.Equal(*before.CurrentPeriodEnd) || !renewal.DueAt.Equal(before.CurrentPeriodEnd.Add(DefaultPaymentGrace)) {
		t.Fatalf("renewal invoice %+v, want an open renewal of the next period, due after the grace", renewal)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.invoices WHERE tenant_id = $1 AND kind = 'renewal'`, paid); n != 1 {
		t.Errorf("%d renewal invoices after two runs, want one", n)
	}

	if err := svc.MarkInvoicePaid(ctx, renewal.ID, " "); err == nil {
		t.Error("an invoice marked paid with no reference")
	}
	if err := svc.MarkInvoicePaid(ctx, renewal.ID, "UTR 4471"); err != nil {
		t.Fatalf("mark the renewal paid: %v", err)
	}
	after, err := svc.GetSubscription(ctx, paid)
	if err != nil {
		t.Fatal(err)
	}
	settled := latestInvoice(t, svc, paid)
	if after.Status != "active" || !after.CurrentPeriodEnd.Equal(renewal.PeriodEnd) || settled.Status != "paid" || settled.PaidAt == nil {
		t.Errorf("after paying the renewal: %+v, invoice %+v; want active for the billed period, paid", after, settled)
	}
	if events(t, paid, "billing.invoice_paid", "") != 1 || events(t, paid, "billing.subscription_renewed", "") != 1 {
		t.Error("paying the renewal wasn't audited as paid and renewed")
	}
	if err := svc.MarkInvoicePaid(ctx, renewal.ID, "UTR 4471"); !errors.Is(err, errs.ErrBillingInvoiceNotOpen) {
		t.Errorf("mark a paid invoice paid again: %v, want invoice_not_open", err)
	}

	endPeriodAgo(t, unpaid, DefaultPaymentGrace+time.Minute)
	if sub, _ := svc.GetSubscription(ctx, unpaid); sub.Grants(time.Now()) {
		t.Error("a renewal unpaid past the grace still grants its plan before the job runs")
	}
	runPeriodEnds(t, svc)
	sub, err := svc.GetSubscription(ctx, unpaid)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Status != "canceled" || tenantPlan(t, unpaid) != "free" || events(t, unpaid, "billing.subscription_ended", "unpaid") != 1 {
		t.Errorf("a renewal unpaid past the grace: %+v, plan %s; want canceled for not paying, free", sub, tenantPlan(t, unpaid))
	}
	if inv := latestInvoice(t, svc, unpaid); inv.Status != "void" {
		t.Errorf("the unpaid renewal is %s, want void", inv.Status)
	}
	if _, err := svc.PayInvoice(ctx, unpaid, latestInvoice(t, svc, unpaid).ID, "https://console.example/ok", "https://console.example/no"); !errors.Is(err, errs.ErrBillingInvoiceNotOpen) {
		t.Errorf("pay a void invoice: %v, want invoice_not_open", err)
	}
}

// TestARenewalIsPaidThroughCheckout checks that a renewal invoice can be paid
// at the provider for exactly its total, which renews the plan and records
// what it was paid with, for that organisation only.
func TestARenewalIsPaidThroughCheckout(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	withSandbox(svc)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	subscribe(t, svc, tenant, "pro", "USD")
	endPeriodAgo(t, tenant, time.Minute)
	runPeriodEnds(t, svc)
	renewal := latestInvoice(t, svc, tenant)

	if _, err := svc.PayInvoice(ctx, other, renewal.ID, "https://console.example/ok", "https://console.example/no"); !errors.Is(err, errs.ErrBillingInvoiceNotFound) {
		t.Errorf("another organisation paying the invoice: %v, want not found", err)
	}
	res, err := svc.PayInvoice(ctx, tenant, renewal.ID, "https://console.example/ok", "https://console.example/no")
	if err != nil {
		t.Fatal(err)
	}
	ref, amount := sandboxCharge(t, res)
	if amount != renewal.AmountMinor {
		t.Errorf("the provider was asked for %d, want the invoice's %d", amount, renewal.AmountMinor)
	}
	if m, err := svc.LastPaymentMethod(ctx, tenant); err != nil || m != nil {
		t.Errorf("payment method before any payment: %+v, %v", m, err)
	}
	if err := svc.CompleteCheckout(ctx, ref, SandboxCard()); err != nil {
		t.Fatal(err)
	}
	sub, err := svc.GetSubscription(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if inv := latestInvoice(t, svc, tenant); inv.ID != renewal.ID || inv.Status != "paid" || sub.Status != "active" || !sub.CurrentPeriodEnd.Equal(renewal.PeriodEnd) {
		t.Errorf("after paying at the provider: %+v, invoice %+v; want the renewal paid and the period renewed", sub, inv)
	}
	m, err := svc.LastPaymentMethod(ctx, tenant)
	if err != nil || m == nil || m.Provider != "sandbox" || m.Type != "card" || m.Last4 != "4242" || m.ExpYear == 0 {
		t.Errorf("payment method %+v, %v; want the sandbox's test card", m, err)
	}
	if m, err := svc.LastPaymentMethod(ctx, other); err != nil || m != nil {
		t.Errorf("another organisation's payment method: %+v, %v", m, err)
	}

	admin := dbtest.User(t, tenant, tenant)
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	var body struct {
		PaymentMethod *SavedPaymentMethod `json:"payment_method"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/billing/payment-method", nil), &body)
	if body.PaymentMethod == nil || body.PaymentMethod.Brand != "visa" {
		t.Errorf("GET payment-method = %+v, want the test card", body.PaymentMethod)
	}
}

// TestInvoiceOnlyActivationIsOpenUntilPaid checks that a plan granted before
// payment leaves its invoice open with a due date, until an operator marks it
// paid with the payment's reference.
func TestInvoiceOnlyActivationIsOpenUntilPaid(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	svc.SetAllowUnpaidActivation(true)
	tenant := dbtest.Tenant(t)
	if _, err := svc.Checkout(ctx, tenant, "pro", "USD", "", "https://console.example/ok", "https://console.example/no"); err != nil {
		t.Fatal(err)
	}
	inv := latestInvoice(t, svc, tenant)
	if inv.Status != "open" || inv.Kind != invoiceKindPurchase || inv.DueAt == nil || inv.DueAt.Before(time.Now().Add(DefaultPaymentGrace-time.Hour)) {
		t.Fatalf("invoice-only activation's invoice %+v, want open and due after the grace", inv)
	}
	if err := svc.MarkInvoicePaid(ctx, uuid.New(), "UTR 1"); !errors.Is(err, errs.ErrBillingInvoiceNotFound) {
		t.Errorf("mark an unknown invoice paid: %v, want not found", err)
	}
	if err := svc.MarkInvoicePaid(ctx, inv.ID, "UTR 9031"); err != nil {
		t.Fatal(err)
	}
	if inv := latestInvoice(t, svc, tenant); inv.Status != "paid" || inv.PaidAt == nil {
		t.Errorf("after the operator marked it paid: %+v", inv)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'billing.invoice_paid'
		AND metadata->>'via' = 'operator' AND metadata->>'reference' = 'UTR 9031'`, tenant); n != 1 {
		t.Errorf("%d operator settlements audited, want one", n)
	}
}

// outbox collects the messages sent through it; fail makes every send fail.
type outbox struct {
	sent []notifier.Message
	fail bool
}

func (o *outbox) Send(_ context.Context, m notifier.Message) error {
	if o.fail {
		return errors.New("transport down")
	}
	o.sent = append(o.sent, m)
	return nil
}

// TestInvoicesKeepWhoTheyWereBilledTo checks that an invoice keeps the billing
// profile it was issued to and the supplier's GSTIN and SAC, and is emailed
// once to that profile's billing email, again after a failed send.
func TestInvoicesKeepWhoTheyWereBilledTo(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	svc.SetTaxConfig(TaxConfig{Enabled: true, SellerCountry: "IN", SellerState: "Karnataka", SupplierGSTIN: "29ABCDE1234F1Z5", SAC: "998315"})
	mail := &outbox{fail: true}
	svc.SetMailer(mail, "https://console.example/")
	tenant, unbilled := dbtest.Tenant(t), dbtest.Tenant(t)
	profile := BillingProfile{LegalName: "Acme Pvt Ltd", BillingEmail: "accounts@acme.example", City: "Pune",
		State: "Maharashtra", Country: "IN", TaxIDType: "gstin", TaxID: "27AAPFU0939F1ZV"}
	if err := svc.UpsertBillingProfile(ctx, tenant, profile); err != nil {
		t.Fatal(err)
	}
	subscribe(t, svc, tenant, "pro", "INR")
	subscribe(t, svc, unbilled, "pro", "INR")
	profile.LegalName = "Acme Technologies Pvt Ltd"
	if err := svc.UpsertBillingProfile(ctx, tenant, profile); err != nil {
		t.Fatal(err)
	}

	inv := latestInvoice(t, svc, tenant)
	if inv.BilledTo == nil || inv.BilledTo.LegalName != "Acme Pvt Ltd" || inv.BilledTo.TaxID != "27AAPFU0939F1ZV" ||
		inv.SupplierGSTIN != "29ABCDE1234F1Z5" || inv.SAC != "998315" {
		t.Errorf("invoice %+v, want who it was billed to when issued, and the supplier's GSTIN and SAC", inv)
	}

	if n, err := svc.SendInvoiceEmails(ctx); err != nil || n != 0 {
		t.Fatalf("send with the transport down: %d, %v", n, err)
	}
	mail.fail = false
	if n, err := svc.SendInvoiceEmails(ctx); err != nil || n != 1 {
		t.Fatalf("send again: %d, %v; want the one invoice with a billing email", n, err)
	}
	if n, err := svc.SendInvoiceEmails(ctx); err != nil || n != 0 {
		t.Errorf("send a third time: %d, %v; want nothing left", n, err)
	}
	if len(mail.sent) != 1 || mail.sent[0].To != "accounts@acme.example" || mail.sent[0].TenantID != tenant.String() {
		t.Fatalf("sent %+v, want one email to the billing address", mail.sent)
	}
	if inv := latestInvoice(t, svc, tenant); inv.EmailedAt == nil {
		t.Error("the invoice doesn't say it was emailed")
	}
}
