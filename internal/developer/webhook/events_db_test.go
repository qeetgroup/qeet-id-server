//go:build integration

package webhook

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/requestsig"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
)

// TestOutboxEventsReachWebhooksOnce checks that a committed event in the
// catalogue reaches its organization's subscriptions once, even when the
// outbox hands it over again, and is sent in the signed envelope; that an
// event outside the catalogue or another organization's isn't; and that a
// delivery the endpoint refuses is not retried.
func TestOutboxEventsReachWebhooksOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, ep := dispatchService(t), newEndpoint(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	sub, otherSub := subscribe(t, svc, organization, ep.URL, "group.created"), subscribe(t, svc, other, ep.URL, "group.created")
	deliveries := func(s *Subscription) int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.webhook_deliveries WHERE subscription_id = $1`, s.ID)
	}

	relay := svc.Relay(&flakyPublisher{failures: 1})
	event := groupCreated(organization)
	if err := relay.Publish(ctx, event); err == nil {
		t.Fatal("the event stream's failure was not returned for the outbox to retry")
	}
	if err := relay.Publish(ctx, event); err != nil {
		t.Fatalf("publish again: %v", err)
	}
	outside := outbox.Message{ID: uuid.New(), EventType: "auth.session.revoked_for_reuse", Payload: event.Payload}
	if err := relay.Publish(ctx, outside); err != nil {
		t.Fatal(err)
	}
	if n, m := deliveries(sub), deliveries(otherSub); n != 1 || m != 0 {
		t.Fatalf("deliveries: %d to the organization's subscription, %d to another's; want 1 and 0", n, m)
	}
	actor := audit.Actor{Type: "user", RequestID: "req-webhook-test"}
	if err := svc.SendTest(ctx, sub, actor); err != nil || deliveries(sub) != 2 {
		t.Fatalf("test event: %v, %d deliveries; want one more though it names only group.created", err, deliveries(sub))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'webhook.test_sent' AND resource_id = $1 AND request_id = $2`, sub.ID, actor.RequestID); n != 1 {
		t.Fatalf("test events recorded: %d, want 1, as the caller's", n)
	}

	dispatch(t, svc)
	sent, n := ep.last("group.created")
	if n != 2 || sent == nil {
		t.Fatalf("endpoint received %d deliveries, want the event and the test", n)
	}
	var body Event
	if err := json.Unmarshal(sent.body, &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	var data struct{ Name string }
	_ = json.Unmarshal(body.Data, &data)
	if body.ID != event.ID || body.Type != "group.created" || body.OrganizationID != organization || body.OccurredAt.IsZero() || data.Name != "Engineering" {
		t.Errorf("delivered %s; want the event's id, type, organization, time and data", sent.body)
	}
	timestamp := sent.header.Get("X-Qeet-Timestamp")
	if sent.header.Get("X-Qeet-Signature") != "sha256="+requestsig.Sign(sub.Secret, timestamp, sent.body) {
		t.Error("the signature doesn't verify with the subscription's secret over the timestamp and body")
	}

	ep.answer(http.StatusGone)
	refused := groupCreated(organization)
	dispatch(t, svc, refused)
	if n := dbtest.Count(t, `
		SELECT count(*) FROM organization.webhook_deliveries WHERE event_id = $1 AND dead_at IS NOT NULL AND attempt = 1
	`, refused.ID); n != 1 {
		t.Error("a delivery the endpoint refused with 410 was not dead-lettered after one attempt")
	}

	// A delivery that used up its attempts gets a fresh budget when retried.
	var gaveUp, owner uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		UPDATE organization.webhook_deliveries SET attempt = $2 WHERE event_id = $1 RETURNING id, subscription_id
	`, refused.ID, maxDeliveryAttempts).Scan(&gaveUp, &owner); err != nil {
		t.Fatal(err)
	}
	// Named under another of the organization's webhooks, it isn't found and is left as it was.
	sibling := subscribe(t, svc, organization, ep.URL, "user.created")
	if err := svc.RetryDelivery(ctx, sibling.ID, gaveUp, organization, actor); !errors.Is(err, ErrDeliveryNotFound) {
		t.Fatalf("retry under another webhook: %v, want ErrWebhookDeliveryNotFound", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.webhook_deliveries WHERE id = $1 AND dead_at IS NOT NULL`, gaveUp); n != 1 {
		t.Fatal("a retry under another webhook re-queued the delivery")
	}
	retried := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'webhook.delivery_retried' AND resource_id = $1 AND request_id = $2`, gaveUp, actor.RequestID)
	}
	if n := retried(); n != 0 {
		t.Fatalf("a refused retry was recorded %d times", n)
	}
	if err := svc.RetryDelivery(ctx, owner, gaveUp, organization, actor); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := retried(); n != 1 {
		t.Fatalf("retries recorded: %d, want 1, as the caller's", n)
	}
	ep.answer(http.StatusServiceUnavailable)
	dispatch(t, svc)
	if n := dbtest.Count(t, `
		SELECT count(*) FROM organization.webhook_deliveries WHERE id = $1 AND dead_at IS NULL AND attempt = 1 AND next_attempt_at > NOW()
	`, gaveUp); n != 1 {
		t.Error("a retried delivery that had used its attempts gave up again at once, want it retrying from its first attempt")
	}
}
