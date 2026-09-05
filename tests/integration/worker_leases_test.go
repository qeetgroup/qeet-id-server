//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

type blockingPublisher struct {
	// target scopes both the block and the tally to the one event under test.
	//
	// platform.outbox is shared by the whole package, so a dispatcher sweep
	// legitimately claims rows other tests enqueued. Blocking on those would
	// deadlock the release sequencing below: the second sweep would park inside
	// Publish on a foreign row, so the main goroutine would never reach
	// close(release) and the first sweep would park forever too.
	target  uuid.UUID
	started chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	ids     []uuid.UUID
}

func (p *blockingPublisher) Publish(_ context.Context, eventID uuid.UUID, _, _ string, _ []byte) error {
	if p.target != uuid.Nil && eventID != p.target {
		return nil // another test's row: let it drain, don't block on it
	}
	p.mu.Lock()
	p.ids = append(p.ids, eventID)
	p.mu.Unlock()
	p.once.Do(func() { close(p.started) })
	<-p.release
	return nil
}

func (p *blockingPublisher) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ids)
}

func TestOutboxLeaseExclusiveAndRecoverable(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	// Retire anything earlier tests left unpublished so this test's event is
	// reliably inside the first claimed batch rather than behind a backlog.
	if _, err := testPool.Exec(ctx,
		`UPDATE platform.outbox SET published_at = NOW() WHERE published_at IS NULL`); err != nil {
		t.Fatalf("drain pre-existing outbox rows: %v", err)
	}
	eventID := uuid.New()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin outbox enqueue: %v", err)
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		ID: eventID, AggregateID: uuid.New(), Topic: "lease.test", EventType: "lease.created", Payload: map[string]any{"ok": true},
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("enqueue outbox event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit outbox event: %v", err)
	}

	publisher := &blockingPublisher{target: eventID, started: make(chan struct{}), release: make(chan struct{})}
	first := outbox.NewDispatcher(testPool, publisher, time.Second, 10)
	second := outbox.NewDispatcher(testPool, publisher, time.Second, 10)
	done := make(chan error, 1)
	go func() { done <- first.Sweep(ctx) }()
	select {
	case <-publisher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first outbox worker did not publish")
	}
	if err := second.Sweep(ctx); err != nil {
		t.Fatalf("second outbox sweep: %v", err)
	}
	if publisher.count() != 1 {
		t.Fatalf("concurrent outbox workers published %d times, want 1", publisher.count())
	}
	close(publisher.release)
	if err := <-done; err != nil {
		t.Fatalf("first outbox sweep: %v", err)
	}
	var published bool
	var leaseOwner *uuid.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT published_at IS NOT NULL, lease_owner FROM platform.outbox WHERE id = $1
	`, eventID).Scan(&published, &leaseOwner); err != nil {
		t.Fatalf("inspect outbox event: %v", err)
	}
	if !published || leaseOwner != nil {
		t.Fatalf("outbox final state published=%v lease_owner=%v", published, leaseOwner)
	}

	recoveredID := uuid.New()
	tx, _ = testPool.Begin(ctx)
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		ID: recoveredID, AggregateID: uuid.New(), Topic: "lease.test", EventType: "lease.recovered", Payload: map[string]any{"ok": true},
	}); err != nil {
		t.Fatalf("enqueue abandoned event: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit abandoned event: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE platform.outbox SET lease_owner = $2, lease_until = NOW() - INTERVAL '1 second' WHERE id = $1
	`, recoveredID, uuid.New()); err != nil {
		t.Fatalf("seed expired outbox lease: %v", err)
	}
	recoveryPublisher := &blockingPublisher{target: recoveredID, started: make(chan struct{}), release: make(chan struct{})}
	close(recoveryPublisher.release)
	recovery := outbox.NewDispatcher(testPool, recoveryPublisher, time.Second, 10)
	if err := recovery.Sweep(ctx); err != nil {
		t.Fatalf("recover expired outbox lease: %v", err)
	}
	if recoveryPublisher.count() != 1 || recoveryPublisher.ids[0] != recoveredID {
		t.Fatalf("recovered outbox IDs = %v, want [%s]", recoveryPublisher.ids, recoveredID)
	}
}

func TestWebhookLeaseExclusiveAndRecoverable(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	var requests atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var headerMu sync.Mutex
	var deliveryIDs []string
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerMu.Lock()
		deliveryIDs = append(deliveryIDs, r.Header.Get("X-Qeet-Delivery-ID"))
		headerMu.Unlock()
		if requests.Add(1) == 1 {
			close(started)
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()

	tenantID := createTenant(t, ctx, uniqueSlug("webhook-lease"))
	first := webhook.NewService(testPool, egress.DevelopmentPolicy())
	second := webhook.NewService(testPool, egress.DevelopmentPolicy())
	first.SetCipher(testEnvelope(t))
	second.SetCipher(testEnvelope(t))
	tx, _ := testPool.Begin(ctx)
	subscription, err := first.Create(ctx, tx, webhook.CreateInput{TenantID: tenantID, URL: endpoint.URL, Events: []string{}})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit webhook: %v", err)
	}
	if err := first.Enqueue(ctx, tenantID, "lease.test", map[string]any{"ok": true}); err != nil {
		t.Fatalf("enqueue webhook: %v", err)
	}
	var deliveryID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT id FROM tenant.webhook_deliveries WHERE subscription_id = $1 ORDER BY created_at LIMIT 1
	`, subscription.ID).Scan(&deliveryID); err != nil {
		t.Fatalf("load delivery ID: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- first.Sweep(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first webhook worker did not deliver")
	}
	if err := second.Sweep(ctx); err != nil {
		t.Fatalf("second webhook sweep: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("concurrent webhook workers delivered %d times, want 1", requests.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first webhook sweep: %v", err)
	}
	headerMu.Lock()
	firstHeader := deliveryIDs[0]
	headerMu.Unlock()
	if firstHeader != deliveryID.String() {
		t.Fatalf("delivery ID header = %q, want %s", firstHeader, deliveryID)
	}

	if err := first.Enqueue(ctx, tenantID, "lease.recovered", map[string]any{"ok": true}); err != nil {
		t.Fatalf("enqueue abandoned webhook: %v", err)
	}
	var recoveredID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT id FROM tenant.webhook_deliveries
		WHERE subscription_id = $1 AND delivered_at IS NULL
		ORDER BY created_at DESC LIMIT 1
	`, subscription.ID).Scan(&recoveredID); err != nil {
		t.Fatalf("load abandoned delivery: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE tenant.webhook_deliveries
		SET lease_owner = $2, lease_until = NOW() - INTERVAL '1 second'
		WHERE id = $1
	`, recoveredID, uuid.New()); err != nil {
		t.Fatalf("seed expired webhook lease: %v", err)
	}
	if err := second.Sweep(ctx); err != nil {
		t.Fatalf("recover expired webhook lease: %v", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("expired webhook lease deliveries = %d, want 2 total", requests.Load())
	}
	headerMu.Lock()
	recoveredHeader := deliveryIDs[1]
	headerMu.Unlock()
	if recoveredHeader != recoveredID.String() {
		t.Fatalf("recovered delivery ID header = %q, want %s", recoveredHeader, recoveredID)
	}
}

func TestGDPRWorkerLeases(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("gdpr-lease"))
	userID := createUserInTenant(t, ctx, tenantID)
	first := gdpr.NewService(testPool, time.Nanosecond)
	second := gdpr.NewService(testPool, time.Nanosecond)
	request, err := first.Request(ctx, gdpr.CreateInput{TenantID: tenantID, UserID: userID})
	if err != nil {
		t.Fatalf("create purge request: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE "user".purge_requests SET grace_until = NOW() - INTERVAL '1 second' WHERE id = $1`, request.ID); err != nil {
		t.Fatalf("make purge due: %v", err)
	}

	blocker, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin user lock: %v", err)
	}
	var lockedUser uuid.UUID
	if err := blocker.QueryRow(ctx, `SELECT id FROM "user".users WHERE id = $1 FOR UPDATE`, userID).Scan(&lockedUser); err != nil {
		t.Fatalf("lock purge user: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- first.Sweep(ctx) }()
	deadline := time.NewTimer(2 * time.Second)
	poll := time.NewTicker(10 * time.Millisecond)
	claimed := false
	for !claimed {
		select {
		case <-deadline.C:
			_ = blocker.Rollback(ctx)
			t.Fatal("purge job was not leased")
		case <-poll.C:
			var owner *uuid.UUID
			if err := testPool.QueryRow(ctx, `SELECT lease_owner FROM "user".purge_requests WHERE id = $1`, request.ID).Scan(&owner); err != nil {
				_ = blocker.Rollback(ctx)
				t.Fatalf("inspect purge lease: %v", err)
			}
			claimed = owner != nil
		}
	}
	poll.Stop()
	deadline.Stop()
	if err := second.Sweep(ctx); err != nil {
		_ = blocker.Rollback(ctx)
		t.Fatalf("second purge sweep: %v", err)
	}
	var state string
	if err := testPool.QueryRow(ctx, `SELECT status FROM "user".purge_requests WHERE id = $1`, request.ID).Scan(&state); err != nil {
		_ = blocker.Rollback(ctx)
		t.Fatalf("read leased purge state: %v", err)
	}
	if state != "pending" {
		_ = blocker.Rollback(ctx)
		t.Fatalf("second worker changed leased purge state to %q", state)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatalf("release user lock: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("first purge sweep: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT status FROM "user".purge_requests WHERE id = $1`, request.ID).Scan(&state); err != nil || state != "completed" {
		t.Fatalf("purge final state = %q (err %v), want completed", state, err)
	}

	exportUserID := createUserInTenant(t, ctx, tenantID)
	exportRequest, err := first.RequestExport(ctx, gdpr.ExportInput{TenantID: tenantID, UserID: exportUserID})
	if err != nil {
		t.Fatalf("create export request: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE "user".export_requests SET lease_owner = $2, lease_until = NOW() + INTERVAL '5 minutes' WHERE id = $1
	`, exportRequest.ID, uuid.New()); err != nil {
		t.Fatalf("seed active export lease: %v", err)
	}
	if err := second.SweepExports(ctx); err != nil {
		t.Fatalf("sweep active export lease: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT status FROM "user".export_requests WHERE id = $1`, exportRequest.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("actively leased export state = %q (err %v), want pending", state, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE "user".export_requests SET lease_until = NOW() - INTERVAL '1 second' WHERE id = $1`, exportRequest.ID); err != nil {
		t.Fatalf("expire export lease: %v", err)
	}
	if err := second.SweepExports(ctx); err != nil {
		t.Fatalf("recover export lease: %v", err)
	}
	var leaseOwner *uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT status, lease_owner FROM "user".export_requests WHERE id = $1`, exportRequest.ID).Scan(&state, &leaseOwner); err != nil {
		t.Fatalf("read recovered export: %v", err)
	}
	if state != "ready" || leaseOwner != nil {
		t.Fatalf("recovered export state=%q lease_owner=%v, want ready/unleased", state, leaseOwner)
	}
}
