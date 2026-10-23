//go:build integration

package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestWebhooksStayInTheirTenant checks that one tenant can neither read nor
// change another tenant's webhook subscription or its deliveries, and that its
// events are never delivered to it.
func TestWebhooksStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := NewService(pool)
	svc.SetCipher(box)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminB := dbtest.User(t, tenantB, tenantB)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	subA, err := svc.Create(ctx, tx, CreateInput{TenantID: tenantA, URL: "https://hooks.example.test/a", Events: []string{"user.created"}})
	if err != nil {
		t.Fatalf("create subscription in A: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := svc.Enqueue(ctx, tenantA, "user.created", map[string]any{"n": 1}); err != nil {
		t.Fatalf("enqueue in A: %v", err)
	}
	var deliveryA uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenant.webhook_deliveries WHERE subscription_id = $1`, subA.ID).Scan(&deliveryA); err != nil {
		t.Fatalf("delivery in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
	path := "/webhooks/" + subA.ID.String()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, path, http.StatusNotFound},
		{http.MethodPost, path + "/test", http.StatusNotFound},
		{http.MethodPost, path + "/deliveries/" + deliveryA.String() + "/retry", http.StatusNotFound},
		{http.MethodDelete, path, http.StatusNotFound},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/webhooks", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path+"/deliveries", nil)); len(ids) != 0 {
		t.Errorf("tenant B sees %d of tenant A's deliveries", len(ids))
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/webhooks", nil)); slices.Contains(ids, subA.ID) {
		t.Error("tenant B's subscription list includes tenant A's")
	}

	if err := svc.Enqueue(ctx, tenantB, "user.created", map[string]any{"n": 2}); err != nil {
		t.Fatalf("enqueue in B: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.webhook_deliveries WHERE subscription_id = $1`, subA.ID); n != 1 {
		t.Errorf("tenant A's subscription has %d deliveries, want only its own 1", n)
	}
	if got, err := svc.Get(ctx, subA.ID, tenantA); err != nil || got.DisabledAt != nil {
		t.Errorf("tenant A's subscription after tenant B's calls: %+v, %v", got, err)
	}
}

// flakyPublisher fails its first failures publishes, then succeeds.
type flakyPublisher struct{ failures int }

func (p *flakyPublisher) Publish(context.Context, outbox.Message) error {
	if p.failures > 0 {
		p.failures--
		return errors.New("stream unavailable")
	}
	return nil
}

// received is one delivery a test endpoint received.
type received struct {
	header http.Header
	body   []byte
}

// endpoint is a webhook receiver that records what it receives and answers
// with the status it is set to.
type endpoint struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	received []received
}

func newEndpoint(t *testing.T) *endpoint {
	e := &endpoint{status: http.StatusOK}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.received = append(e.received, received{r.Header.Clone(), body})
		status := e.status
		e.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *endpoint) answer(status int) {
	e.mu.Lock()
	e.status = status
	e.mu.Unlock()
}

// last returns the latest delivery received of event type, and how many were
// received in all.
func (e *endpoint) last(eventType string) (*received, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var found *received
	for i := range e.received {
		if e.received[i].header.Get("X-Qeet-Event") == eventType {
			found = &e.received[i]
		}
	}
	return found, len(e.received)
}

// dispatchService returns a webhook service that may deliver to a local
// endpoint.
func dispatchService(t *testing.T) *Service {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := NewService(dbtest.Pool(t), egress.DevelopmentPolicy())
	svc.SetCipher(box)
	return svc
}

// subscribe subscribes url to events in tenant.
func subscribe(t *testing.T, svc *Service, tenant uuid.UUID, url string, events ...string) *Subscription {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	sub, err := svc.Create(ctx, tx, CreateInput{TenantID: tenant, URL: url, Events: events})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return sub
}

// groupCreated returns a group.created outbox event of tenant.
func groupCreated(tenant uuid.UUID) outbox.Message {
	return outbox.Message{
		ID: uuid.New(), Topic: "group.events", EventType: "group.created", OccurredAt: time.Now(),
		Payload: []byte(fmt.Sprintf(`{"tenant_id": %q, "name": "Engineering"}`, tenant)),
	}
}

// dispatch publishes each event through svc's relay and runs one dispatch.
func dispatch(t *testing.T, svc *Service, events ...outbox.Message) {
	t.Helper()
	relay := svc.Relay(outbox.LogPublisher{})
	for _, e := range events {
		if err := relay.Publish(dbtest.Context(t), e); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	if err := svc.tick(dbtest.Context(t)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

// TestOutboxEventsReachWebhooksOnce checks that a committed event in the
// catalogue reaches its organisation's subscriptions once, even when the
// outbox hands it over again, and is sent in the signed envelope; that an
// event outside the catalogue or another organisation's isn't; and that a
// delivery the endpoint refuses is not retried.
func TestOutboxEventsReachWebhooksOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, ep := dispatchService(t), newEndpoint(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	sub, otherSub := subscribe(t, svc, tenant, ep.URL, "group.created"), subscribe(t, svc, other, ep.URL, "group.created")
	deliveries := func(s *Subscription) int {
		return dbtest.Count(t, `SELECT count(*) FROM tenant.webhook_deliveries WHERE subscription_id = $1`, s.ID)
	}

	relay := svc.Relay(&flakyPublisher{failures: 1})
	event := groupCreated(tenant)
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
		t.Fatalf("deliveries: %d to the organisation's subscription, %d to another's; want 1 and 0", n, m)
	}
	if err := svc.SendTest(ctx, sub); err != nil || deliveries(sub) != 2 {
		t.Fatalf("test event: %v, %d deliveries; want one more though it names only group.created", err, deliveries(sub))
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
	if body.ID != event.ID || body.Type != "group.created" || body.TenantID != tenant || body.OccurredAt.IsZero() || data.Name != "Engineering" {
		t.Errorf("delivered %s; want the event's id, type, organisation, time and data", sent.body)
	}
	timestamp := sent.header.Get("X-Qeet-Timestamp")
	if sent.header.Get("X-Qeet-Signature") != "sha256="+sign(sub.Secret, timestamp, sent.body) {
		t.Error("the signature doesn't verify with the subscription's secret over the timestamp and body")
	}

	ep.answer(http.StatusGone)
	refused := groupCreated(tenant)
	dispatch(t, svc, refused)
	if n := dbtest.Count(t, `
		SELECT count(*) FROM tenant.webhook_deliveries WHERE event_id = $1 AND dead_at IS NOT NULL AND attempt = 1
	`, refused.ID); n != 1 {
		t.Error("a delivery the endpoint refused with 410 was not dead-lettered after one attempt")
	}
}

// alerts records the in-app alerts sent.
type alerts struct {
	mu    sync.Mutex
	users []uuid.UUID
}

func (a *alerts) Notify(_ context.Context, _, userID uuid.UUID, _, _, _, _ string) error {
	a.mu.Lock()
	a.users = append(a.users, userID)
	a.mu.Unlock()
	return nil
}

// TestFailingSubscriptionIsDisabled checks that a success clears a
// subscription's failures, that one failing for three days is disabled,
// audited and its organisation's webhook managers alone are alerted, and that
// enabling it again delivers what was queued meanwhile.
func TestFailingSubscriptionIsDisabled(t *testing.T) {
	svc, ep := dispatchService(t), newEndpoint(t)
	sent := &alerts{}
	svc.SetNotifier(sent)
	tenant := dbtest.Tenant(t)
	manager := dbtest.User(t, tenant)
	dbtest.Assign(t, manager.ID, tenant, dbtest.Role(t, tenant, "webhook.write"))
	dbtest.User(t, tenant, tenant) // a member who doesn't manage webhooks
	sub := subscribe(t, svc, tenant, ep.URL, "group.created")
	state := func() (failing, disabled bool, reason string) {
		var r *string
		if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
			SELECT failing_since IS NOT NULL, disabled_at IS NOT NULL, disabled_reason FROM tenant.webhook_subscriptions WHERE id = $1
		`, sub.ID).Scan(&failing, &disabled, &r); err != nil {
			t.Fatal(err)
		}
		if r != nil {
			reason = *r
		}
		return failing, disabled, reason
	}
	retryNow := func() {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE tenant.webhook_deliveries SET next_attempt_at = NOW() WHERE subscription_id = $1`, sub.ID); err != nil {
			t.Fatal(err)
		}
	}

	ep.answer(http.StatusServiceUnavailable)
	dispatch(t, svc, groupCreated(tenant))
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
	dispatch(t, svc, groupCreated(tenant))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE tenant.webhook_subscriptions SET failing_since = NOW() - interval '4 days' WHERE id = $1`, sub.ID); err != nil {
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
	dispatch(t, svc, groupCreated(tenant))
	if _, after := ep.last("group.created"); after != before {
		t.Fatal("a disabled subscription was delivered to")
	}
	asManager := dbtest.Serve(dbtest.Principal(manager.ID, tenant), (&Handler{Service: svc}).Mount)
	path := "/tenants/" + tenant.String() + "/webhooks/" + sub.ID.String() + "/enable"
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

// TestRotatedSecretOverlaps checks that after a rotation deliveries are signed
// with the new secret and the old one until the overlap ends, then the new
// one alone.
func TestRotatedSecretOverlaps(t *testing.T) {
	svc, ep := dispatchService(t), newEndpoint(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant)
	dbtest.Assign(t, admin.ID, tenant, dbtest.Role(t, tenant, "webhook.write"))
	sub := subscribe(t, svc, tenant, ep.URL, "group.created")

	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/tenants/"+tenant.String()+"/webhooks/"+sub.ID.String()+"/rotate-secret", nil)
	var rotated struct {
		Secret                  string    `json:"secret"`
		PreviousSecretExpiresAt time.Time `json:"previous_secret_expires_at"`
	}
	dbtest.Decode(t, rec, &rotated)
	if rec.Code != http.StatusOK || rotated.Secret == "" || rotated.Secret == sub.Secret ||
		time.Until(rotated.PreviousSecretExpiresAt) < SecretRotationOverlap-time.Minute {
		t.Fatalf("rotate: %d %s; want a new secret and the old one kept for the overlap", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'webhook.secret_rotated' AND resource_id = $1`, sub.ID); n != 1 {
		t.Error("the rotation was not audited")
	}

	dispatch(t, svc, groupCreated(tenant))
	got, _ := ep.last("group.created")
	timestamp := got.header.Get("X-Qeet-Timestamp")
	want := "sha256=" + sign(rotated.Secret, timestamp, got.body) + ",sha256=" + sign(sub.Secret, timestamp, got.body)
	if got.header.Get("X-Qeet-Signature") != want {
		t.Errorf("during the overlap: signature %q; want the new secret's then the old one's", got.header.Get("X-Qeet-Signature"))
	}

	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE tenant.webhook_subscriptions SET previous_secret_expires_at = NOW() - interval '1 minute' WHERE id = $1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	dispatch(t, svc, groupCreated(tenant))
	got, _ = ep.last("group.created")
	if want := "sha256=" + sign(rotated.Secret, got.header.Get("X-Qeet-Timestamp"), got.body); got.header.Get("X-Qeet-Signature") != want {
		t.Errorf("after the overlap: signature %q; want the new secret's alone", got.header.Get("X-Qeet-Signature"))
	}
}
