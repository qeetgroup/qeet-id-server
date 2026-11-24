//go:build integration

package webhook

import (
	"context"
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

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestWebhooksStayInTheirOrganization checks that one organization can neither read nor
// change another organization's webhook subscription or its deliveries, and that its
// events are never delivered to it.
func TestWebhooksStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := testService(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminA, adminB := dbtest.User(t, organizationA, organizationA), dbtest.User(t, organizationB, organizationB)

	subA, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, URL: "https://hooks.example.test/a", Events: []string{"user.created"}},
		audit.Actor{UserID: &adminA.ID, Type: "user"})
	if err != nil {
		t.Fatalf("create subscription in A: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.webhook_subscriptions WHERE id = $1 AND organization_id = $2 AND created_by = $3`, subA.ID, organizationA, adminA.ID); n != 1 {
		t.Error("the subscription doesn't record who created it")
	}
	if err := svc.Enqueue(ctx, organizationA, "user.created", map[string]any{"n": 1}); err != nil {
		t.Fatalf("enqueue in A: %v", err)
	}
	var deliveryA uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organization.webhook_deliveries WHERE subscription_id = $1`, subA.ID).Scan(&deliveryA); err != nil {
		t.Fatalf("delivery in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc}).Mount)
	path := "/webhooks/" + subA.ID.String()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, path, http.StatusNotFound},
		{http.MethodPost, path + "/test", http.StatusNotFound},
		{http.MethodPost, path + "/deliveries/" + deliveryA.String() + "/retry", http.StatusNotFound},
		{http.MethodDelete, path, http.StatusNotFound},
		{http.MethodGet, "/organizations/" + organizationA.String() + "/webhooks", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("organization B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, path+"/deliveries", nil)); len(ids) != 0 {
		t.Errorf("organization B sees %d of organization A's deliveries", len(ids))
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/webhooks", nil)); slices.Contains(ids, subA.ID) {
		t.Error("organization B's subscription list includes organization A's")
	}

	if err := svc.Enqueue(ctx, organizationB, "user.created", map[string]any{"n": 2}); err != nil {
		t.Fatalf("enqueue in B: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.webhook_deliveries WHERE subscription_id = $1`, subA.ID); n != 1 {
		t.Errorf("organization A's subscription has %d deliveries, want only its own 1", n)
	}
	if got, err := svc.Get(ctx, subA.ID, organizationA); err != nil || got.DisabledAt != nil {
		t.Errorf("organization A's subscription after organization B's calls: %+v, %v", got, err)
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

// testDeps are a webhook service's dependencies for a test: a fixed cipher,
// every plan including webhooks, and alerts recorded.
func testDeps(t *testing.T) Deps {
	t.Helper()
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return Deps{Cipher: box, PlanGate: allPlans{}, Notifier: &alerts{}}
}

// testService returns a webhook service built with testDeps, changed by each
// of change.
func testService(t *testing.T, change ...func(*Deps)) *Service {
	t.Helper()
	d := testDeps(t)
	for _, c := range change {
		c(&d)
	}
	svc, err := NewService(dbtest.Pool(t), d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// dispatchService returns a webhook service that may deliver to a local
// endpoint, changed by each of change.
func dispatchService(t *testing.T, change ...func(*Deps)) *Service {
	t.Helper()
	return testService(t, append([]func(*Deps){func(d *Deps) { d.Egress = egress.DevelopmentPolicy() }}, change...)...)
}

// allPlans includes webhooks in every organization's plan.
type allPlans struct{}

func (allPlans) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return true, nil }

// subscribe subscribes url to events in organization.
func subscribe(t *testing.T, svc *Service, organization uuid.UUID, url string, events ...string) *Subscription {
	t.Helper()
	sub, err := svc.Create(dbtest.Context(t), CreateInput{OrganizationID: organization, URL: url, Events: events}, audit.Actor{Type: "system"})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	return sub
}

// groupCreated returns a group.created outbox event of organization.
func groupCreated(organization uuid.UUID) outbox.Message {
	return outbox.Message{
		ID: uuid.New(), Topic: "group.events", EventType: "group.created", OccurredAt: time.Now(),
		Payload: []byte(fmt.Sprintf(`{"organization_id": %q, "name": "Engineering"}`, organization)),
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

// planGate includes webhooks in the plans of the organizations it holds.
type planGate map[uuid.UUID]bool

func (g planGate) FeatureAllowed(_ context.Context, organizationID uuid.UUID, _ string) (bool, error) {
	return g[organizationID], nil
}
