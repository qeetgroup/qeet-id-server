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

// TestOutboxEventsReachWebhooksOnce checks that a committed event in the
// catalogue reaches its organisation's subscriptions once, even when the
// outbox hands it over again, and is sent in the signed envelope; that an
// event outside the catalogue or another organisation's isn't; and that a
// delivery the endpoint refuses is not retried.
func TestOutboxEventsReachWebhooksOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc := NewService(pool, egress.DevelopmentPolicy())
	svc.SetCipher(box)

	type received struct {
		header http.Header
		body   []byte
	}
	var (
		mu     sync.Mutex
		got    []received
		answer = http.StatusOK
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, received{r.Header.Clone(), body})
		status := answer
		mu.Unlock()
		w.WriteHeader(status)
	}))
	defer srv.Close()

	subscribe := func(tenant uuid.UUID, events ...string) *Subscription {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		sub, err := svc.Create(ctx, tx, CreateInput{TenantID: tenant, URL: srv.URL, Events: events})
		if err != nil {
			t.Fatalf("subscribe: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return sub
	}
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	sub, otherSub := subscribe(tenant, "group.created"), subscribe(other, "group.created")
	deliveries := func(s *Subscription) int {
		return dbtest.Count(t, `SELECT count(*) FROM tenant.webhook_deliveries WHERE subscription_id = $1`, s.ID)
	}

	relay := svc.Relay(&flakyPublisher{failures: 1})
	event := outbox.Message{
		ID: uuid.New(), Topic: "group.events", EventType: "group.created", OccurredAt: time.Now(),
		Payload: []byte(fmt.Sprintf(`{"tenant_id": %q, "name": "Engineering"}`, tenant)),
	}
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

	if err := svc.tick(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	mu.Lock()
	var sent *received
	for i := range got {
		if got[i].header.Get("X-Qeet-Event") == "group.created" {
			sent = &got[i]
		}
	}
	n := len(got)
	mu.Unlock()
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

	mu.Lock()
	answer = http.StatusGone
	mu.Unlock()
	refused := outbox.Message{ID: uuid.New(), EventType: "group.created", OccurredAt: time.Now(), Payload: event.Payload}
	if err := relay.Publish(ctx, refused); err != nil {
		t.Fatal(err)
	}
	if err := svc.tick(ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM tenant.webhook_deliveries WHERE event_id = $1 AND dead_at IS NOT NULL AND attempt = 1
	`, refused.ID); n != 1 {
		t.Error("a delivery the endpoint refused with 410 was not dead-lettered after one attempt")
	}
}
