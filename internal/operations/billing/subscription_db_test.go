//go:build integration

package billing

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPlanChangesCommitWithTheirAuditEvents checks that switching plan and
// cancelling are each recorded in the transaction that makes them: refused
// together when the event can't be written, and recorded once when it can.
func TestPlanChangesCommitWithTheirAuditEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	organization := dbtest.Organization(t)
	subscribe(t, svc, organization, "pro", "USD")
	actor := audit.Actor{Type: "system"}

	refuseAudit(t, organization, "billing.plan_changed")
	if _, err := svc.SwitchPlan(ctx, organization, "starter", "USD", actor); err == nil {
		t.Fatal("switch plan while its audit event can't be written: no error")
	}
	if got := planOf(t, svc, organization); got != "pro" {
		t.Errorf("plan after a failed audit write = %q, want pro", got)
	}
	refuseAudit(t, organization, "billing.subscription_canceled")
	if err := svc.CancelAtPeriodEnd(ctx, organization, actor); err == nil {
		t.Fatal("cancel while its audit event can't be written: no error")
	}
	if sub, err := svc.GetSubscription(ctx, organization); err != nil || sub.CancelAtPeriodEnd {
		t.Errorf("subscription after a failed audit write: %+v, %v; want it still renewing", sub, err)
	}

	other := dbtest.Organization(t)
	subscribe(t, svc, other, "pro", "USD")
	if _, err := svc.SwitchPlan(ctx, other, "starter", "USD", actor); err != nil {
		t.Fatal(err)
	}
	if err := svc.CancelAtPeriodEnd(ctx, other, actor); err != nil {
		t.Fatal(err)
	}
	if n := events(t, other, "billing.plan_changed", ""); n != 1 {
		t.Errorf("%d plan changes recorded, want 1", n)
	}
	if n := events(t, other, "billing.subscription_canceled", ""); n != 1 {
		t.Errorf("%d cancellations recorded, want 1", n)
	}
}

// TestEffectivePlanFollowsTheSubscription checks the plan an organization is
// on: its subscription's while that grants it, free once it lapses, with no
// subscription the plan its record names, and free when that can't be read or
// there is nothing to read it from.
func TestEffectivePlanFollowsTheSubscription(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t)
	label := func(plan string, err error) PlanLabel {
		return func(context.Context, uuid.UUID) (string, error) { return plan, err }
	}
	subscribed, lapsed, unsubscribed := dbtest.Organization(t), dbtest.Organization(t), dbtest.Organization(t)
	subscribe(t, svc, subscribed, "pro", "USD")
	subscribe(t, svc, lapsed, "pro", "USD")
	lapse(t, lapsed)
	cancelSubscription(t, svc, lapsed)

	for _, c := range []struct {
		name         string
		resolver     PlanResolver
		organization uuid.UUID
		want         string
	}{
		{"a granting subscription", PlanResolver{Billing: svc, Label: label("starter", nil)}, subscribed, "pro"},
		{"a lapsed subscription", PlanResolver{Billing: svc, Label: label("enterprise", nil)}, lapsed, "free"},
		{"no subscription", PlanResolver{Billing: svc, Label: label("starter", nil)}, unsubscribed, "starter"},
		{"no subscription, the label unreadable", PlanResolver{Billing: svc, Label: label("starter", errors.New("down"))}, unsubscribed, "free"},
		{"no subscription, no label", PlanResolver{Billing: svc}, unsubscribed, "free"},
		{"no billing", PlanResolver{Label: label("pro", nil)}, subscribed, "pro"},
	} {
		if got, err := c.resolver.EffectivePlan(ctx, c.organization); err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}
