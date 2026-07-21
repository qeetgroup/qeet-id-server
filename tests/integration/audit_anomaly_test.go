//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/anomaly"
)

func recordAuditEvent(t *testing.T, ctx context.Context, tenantID, actorID uuid.UUID, action, ip string) {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  &actorID,
		ActorType:    "user",
		Action:       action,
		ResourceType: "role",
		IP:           ip,
	}); err != nil {
		t.Fatalf("audit.Record: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestAuditAnomalySweep builds up a behavioral baseline for one actor from
// 25 identical events (same action, same IP), then records one event that
// diverges on both signals (new action type, new IP) — score
// weightAction+weightIP = 0.7, above the default 0.6 threshold. The sweep
// should flag exactly that one event, and only after the cold-start guard
// (min_baseline_events=20) has been satisfied.
func TestAuditAnomalySweep(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("anom"))
	actorID := createUserInTenant(t, ctx, tenantID)

	for i := 0; i < 25; i++ {
		recordAuditEvent(t, ctx, tenantID, actorID, "role.assigned", "10.0.0.1")
	}
	recordAuditEvent(t, ctx, tenantID, actorID, "billing.plan_changed", "203.0.113.5")

	svc := anomaly.NewService(testPool)
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	anomalies, err := svc.List(ctx, tenantID, "open", 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(anomalies) != 1 {
		t.Fatalf("open anomalies = %d, want 1 (%+v)", len(anomalies), anomalies)
	}
	got := anomalies[0]
	if got.Action != "billing.plan_changed" {
		t.Errorf("flagged action = %q, want billing.plan_changed", got.Action)
	}
	if got.Score < 0.65 {
		t.Errorf("score = %v, want >= 0.65 (action+ip novelty)", got.Score)
	}
	wantReasons := map[string]bool{"new_action_type": false, "new_ip": false}
	for _, r := range got.Reasons {
		if _, ok := wantReasons[r]; ok {
			wantReasons[r] = true
		}
	}
	for reason, seen := range wantReasons {
		if !seen {
			t.Errorf("reasons = %v, missing %q", got.Reasons, reason)
		}
	}

	// Every audit.events row for this actor is now scored exactly once —
	// running the sweep again must not double-flag anything.
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	anomalies, err = svc.List(ctx, tenantID, "", 50)
	if err != nil {
		t.Fatalf("list after second sweep: %v", err)
	}
	if len(anomalies) != 1 {
		t.Fatalf("anomalies after re-sweep = %d, want still 1", len(anomalies))
	}

	// Resolve clears it from the open list.
	if err := svc.Resolve(ctx, tenantID, got.ID, actorID); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	open, err := svc.List(ctx, tenantID, "open", 50)
	if err != nil {
		t.Fatalf("list open after resolve: %v", err)
	}
	if len(open) != 0 {
		t.Fatalf("open anomalies after resolve = %d, want 0", len(open))
	}
}

// TestAuditAnomalySettings exercises the per-tenant threshold/enable knobs.
func TestAuditAnomalySettings(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("anomset"))
	actorID := createUserInTenant(t, ctx, tenantID)
	svc := anomaly.NewService(testPool)

	// Disable detection entirely — even a wildly novel event after plenty of
	// history must not be flagged.
	if _, err := svc.UpdateSettings(ctx, tenantID, anomaly.Settings{Enabled: false, ScoreThreshold: 0.6, MinBaselineEvents: 20}); err != nil {
		t.Fatalf("update settings: %v", err)
	}
	for i := 0; i < 25; i++ {
		recordAuditEvent(t, ctx, tenantID, actorID, "role.assigned", "10.0.0.1")
	}
	recordAuditEvent(t, ctx, tenantID, actorID, "billing.plan_changed", "203.0.113.5")
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	anomalies, err := svc.List(ctx, tenantID, "", 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(anomalies) != 0 {
		t.Fatalf("anomalies with detection disabled = %d, want 0", len(anomalies))
	}
}
