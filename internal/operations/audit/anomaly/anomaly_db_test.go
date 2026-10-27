//go:build integration

package anomaly

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestScoreOneUsesOneConnection checks that scoring an event, settings read
// included, runs on its own transaction's connection.
func TestScoreOneUsesOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	actor := dbtest.User(t, tenant, tenant)
	svc := NewService(pool)
	if _, err := svc.UpdateSettings(ctx, tenant, Settings{Enabled: true, ScoreThreshold: 0.6, MinBaselineEvents: 5}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	e := unscoredEvent{ID: uuid.New(), TenantID: &tenant, ActorUserID: &actor.ID, Action: "user.updated",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit.events (id, tenant_id, actor_user_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, $3, 'user', $4, 'user', $5)
	`, e.ID, tenant, actor.ID, e.Action, e.CreatedAt); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	dbtest.LeaveOneConnection(t)
	scoreCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if done, err := svc.scoreOne(scoreCtx, e); err != nil || !done {
		t.Fatalf("score with one free connection: %v, %v", done, err)
	}
	var scored bool
	var baseline int64
	if err := pool.QueryRow(ctx, `
		SELECT e.scored_at IS NOT NULL, b.event_count
		FROM audit.events e
		JOIN audit.actor_baselines b ON b.tenant_id = e.tenant_id AND b.actor_user_id = e.actor_user_id
		WHERE e.id = $1 AND e.tenant_id = $2
	`, e.ID, tenant).Scan(&scored, &baseline); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !scored || baseline != 1 {
		t.Errorf("after scoring: scored %v, baseline %d events; want true, 1", scored, baseline)
	}
}

// TestSweepKeepsUpAndSkipsHeldEvents checks that one sweep scores a backlog
// larger than a batch, and that an event another instance is scoring is
// skipped rather than waited for.
func TestSweepKeepsUpAndSkipsHeldEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	tenant := dbtest.Tenant(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit.events (id, tenant_id, actor_type, action, resource_type, created_at)
		SELECT gen_random_uuid(), $1, 'system', 'tenant.updated', 'tenant', NOW() - make_interval(secs => g)
		FROM generate_series(1, $2::int) g
	`, tenant, 2*sweepBatch+5); err != nil {
		t.Fatal(err)
	}
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND scored_at IS NULL`, tenant); n != 0 {
		t.Errorf("%d events left unscored after one sweep", n)
	}

	held := unscoredEvent{ID: uuid.New(), TenantID: &tenant, Action: "tenant.updated", CreatedAt: time.Now()}
	if _, err := pool.Exec(ctx, `INSERT INTO audit.events (id, tenant_id, actor_type, action, resource_type) VALUES ($1, $2, 'system', 'tenant.updated', 'tenant')`, held.ID, tenant); err != nil {
		t.Fatal(err)
	}
	other, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Rollback(context.Background()) }()
	if _, err := other.Exec(ctx, `SELECT 1 FROM audit.events WHERE id = $1 FOR UPDATE`, held.ID); err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if done, err := svc.scoreOne(waitCtx, held); err != nil || done {
		t.Errorf("an event another instance holds: scored %v, %v; want it skipped at once", done, err)
	}
}
