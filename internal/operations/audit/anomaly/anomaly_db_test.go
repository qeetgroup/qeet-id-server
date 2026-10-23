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
	if err := svc.scoreOne(scoreCtx, e); err != nil {
		t.Fatalf("score with one free connection: %v", err)
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
