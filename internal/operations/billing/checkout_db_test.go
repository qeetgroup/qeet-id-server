//go:build integration

package billing

import (
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestACheckoutCompletedTwiceChangesNothingMore checks that a payment provider sending the same
// completion again, as a webhook retry does, is answered without error and changes nothing more: the
// organization keeps one paid invoice and one audited plan change, and its period isn't extended.
func TestACheckoutCompletedTwiceChangesNothingMore(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, taxed, withSandbox)
	organization := dbtest.Organization(t)
	if err := svc.UpsertBillingProfile(ctx, organization, BillingProfile{Country: "IN", State: "Maharashtra"}); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Checkout(ctx, organization, "starter", "INR", "IN", "https://app.example/ok", "https://app.example/cancel")
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	ref, _ := sandboxCharge(t, res)

	type state struct {
		invoices, paid, auditRows int
		periodEnd                 time.Time
	}
	read := func() state {
		t.Helper()
		var s state
		s.invoices = dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1`, organization)
		s.paid = dbtest.Count(t, `SELECT count(*) FROM organization.invoices WHERE organization_id = $1 AND status = 'paid'`, organization)
		s.auditRows = dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1`, organization)
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT current_period_end FROM organization.subscriptions WHERE organization_id = $1`,
			organization).Scan(&s.periodEnd); err != nil {
			t.Fatalf("subscription: %v", err)
		}
		return s
	}

	if err := svc.CompleteCheckout(ctx, ref, nil); err != nil {
		t.Fatalf("complete checkout: %v", err)
	}
	once := read()
	if once.paid != 1 {
		t.Fatalf("after the payment: %d paid invoices, want 1", once.paid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'billing.plan_changed'
		AND metadata->>'via' = 'checkout' AND metadata->>'plan' = 'starter'`, organization); n != 1 {
		t.Fatalf("plan changes audited after the payment: %d, want 1", n)
	}
	if err := svc.CompleteCheckout(ctx, ref, nil); err != nil {
		t.Fatalf("the same completion again: %v, want it accepted so the provider stops retrying", err)
	}
	if again := read(); again != once {
		t.Errorf("the same completion again changed the organization: %+v, was %+v", again, once)
	}
}
