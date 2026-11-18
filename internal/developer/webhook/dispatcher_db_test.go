//go:build integration

package webhook

import (
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestFailingSubscriptionIsDisabled checks that a success clears a
// subscription's failures, that one failing for three days is disabled,
// audited and its organization's webhook managers alone are alerted, and that
// enabling it again delivers what was queued meanwhile.
func TestFailingSubscriptionIsDisabled(t *testing.T) {
	sent := &alerts{}
	svc, ep := dispatchService(t, func(d *Deps) { d.Notifier = sent }), newEndpoint(t)
	organization := dbtest.Organization(t)
	manager := dbtest.User(t, organization)
	dbtest.Assign(t, manager.ID, organization, dbtest.Role(t, organization, "webhook.write"))
	dbtest.User(t, organization, organization) // a member who doesn't manage webhooks
	sub := subscribe(t, svc, organization, ep.URL, "group.created")
	state := func() (failing, disabled bool, reason string) {
		var r *string
		if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
			SELECT failing_since IS NOT NULL, disabled_at IS NOT NULL, disabled_reason FROM organization.webhook_subscriptions WHERE id = $1
		`, sub.ID).Scan(&failing, &disabled, &r); err != nil {
			t.Fatal(err)
		}
		if r != nil {
			reason = *r
		}
		return failing, disabled, reason
	}
	retryNow := func() {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.webhook_deliveries SET next_attempt_at = NOW() WHERE subscription_id = $1`, sub.ID); err != nil {
			t.Fatal(err)
		}
	}

	ep.answer(http.StatusServiceUnavailable)
	dispatch(t, svc, groupCreated(organization))
	if failing, disabled, _ := state(); !failing || disabled {
		t.Fatalf("after one failure: failing %v, disabled %v; want failing and still enabled", failing, disabled)
	}
	ep.answer(http.StatusOK)
	retryNow()
	dispatch(t, svc)
	if failing, _, _ := state(); failing {
		t.Fatal("a successful delivery didn't clear the failures")
	}

	ep.answer(http.StatusServiceUnavailable)
	dispatch(t, svc, groupCreated(organization))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.webhook_subscriptions SET failing_since = NOW() - interval '4 days' WHERE id = $1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	retryNow()
	dispatch(t, svc)
	if _, disabled, reason := state(); !disabled || reason != "failing" {
		t.Fatalf("after failing for 4 days: disabled %v (%q); want disabled as failing", disabled, reason)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'webhook.subscription_auto_disabled' AND resource_id = $1`, sub.ID); n != 1 {
		t.Error("the automatic disabling was not audited")
	}
	if !slices.Equal(sent.users, []uuid.UUID{manager.ID}) {
		t.Errorf("alerted %v; want the webhook manager %s alone", sent.users, manager.ID)
	}

	ep.answer(http.StatusOK)
	_, before := ep.last("group.created")
	dispatch(t, svc, groupCreated(organization))
	if _, after := ep.last("group.created"); after != before {
		t.Fatal("a disabled subscription was delivered to")
	}
	asManager := dbtest.Serve(dbtest.Principal(manager.ID, organization), (&Handler{Service: svc}).Mount)
	path := "/organizations/" + organization.String() + "/webhooks/" + sub.ID.String() + "/enable"
	if rec := dbtest.Do(t, asManager, http.MethodPost, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	if failing, disabled, _ := state(); failing || disabled {
		t.Fatalf("after enabling: failing %v, disabled %v; want neither", failing, disabled)
	}
	retryNow()
	dispatch(t, svc)
	if _, after := ep.last("group.created"); after <= before {
		t.Error("deliveries queued while it was disabled were not sent once enabled")
	}
}

// TestLapsedPlanStopsDeliveries checks that a subscription set up while the
// plan included webhooks delivers nothing once the plan has lapsed: its
// deliveries are dead-lettered unsent, and one sent again after paying again
// goes out.
func TestLapsedPlanStopsDeliveries(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	plans := planGate{organization: true}
	svc, ep := dispatchService(t, func(d *Deps) { d.PlanGate = plans }), newEndpoint(t)
	subscribe(t, svc, organization, ep.URL, "group.created")

	delete(plans, organization) // the plan lapses
	event := groupCreated(organization)
	dispatch(t, svc, event)
	if _, n := ep.last("group.created"); n != 0 {
		t.Fatalf("endpoint received %d deliveries after the plan lapsed, want none", n)
	}
	var id, owner uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		SELECT id, subscription_id FROM organization.webhook_deliveries WHERE event_id = $1 AND dead_at IS NOT NULL AND attempt = 0 AND error = $2
	`, event.ID, errNotInPlan).Scan(&id, &owner); err != nil {
		t.Fatalf("the delivery was not dead-lettered unsent: %v", err)
	}

	plans[organization] = true // paid again
	if err := svc.RetryDelivery(ctx, owner, id, organization); err != nil {
		t.Fatal(err)
	}
	dispatch(t, svc)
	if _, n := ep.last("group.created"); n != 1 {
		t.Errorf("endpoint received %d deliveries once paid again, want 1", n)
	}
}
