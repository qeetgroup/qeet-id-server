//go:build integration

package anomaly

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestScoreOneUsesOneConnection checks that scoring an event, settings read
// included, runs on its own transaction's connection.
func TestScoreOneUsesOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	actor := dbtest.User(t, organization, organization)
	svc := NewService(pool)
	if _, err := svc.UpdateSettings(ctx, organization, Settings{Enabled: true, ScoreThreshold: 0.6, MinBaselineEvents: 5}); err != nil {
		t.Fatalf("save settings: %v", err)
	}
	e := unscoredEvent{ID: uuid.New(), OrganizationID: &organization, ActorUserID: &actor.ID, Action: "user.updated",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit.events (id, organization_id, actor_user_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, $3, 'user', $4, 'user', $5)
	`, e.ID, organization, actor.ID, e.Action, e.CreatedAt); err != nil {
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
		JOIN audit.actor_baselines b ON b.organization_id = e.organization_id AND b.actor_user_id = e.actor_user_id
		WHERE e.id = $1 AND e.organization_id = $2
	`, e.ID, organization).Scan(&scored, &baseline); err != nil {
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
	organization := dbtest.Organization(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type, created_at)
		SELECT gen_random_uuid(), $1, 'system', 'organization.updated', 'organization', NOW() - make_interval(secs => g)
		FROM generate_series(1, $2::int) g
	`, organization, 2*sweepBatch+5); err != nil {
		t.Fatal(err)
	}
	if err := svc.tick(ctx); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND scored_at IS NULL`, organization); n != 0 {
		t.Errorf("%d events left unscored after one sweep", n)
	}

	held := unscoredEvent{ID: uuid.New(), OrganizationID: &organization, Action: "organization.updated", CreatedAt: time.Now()}
	if _, err := pool.Exec(ctx, `INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type) VALUES ($1, $2, 'system', 'organization.updated', 'organization')`, held.ID, organization); err != nil {
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

// TestListFiltersByStatus checks that the list holds the organization's open
// or resolved anomalies, or all of them without a status, newest first, page
// by page, and never another organization's.
func TestListFiltersByStatus(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	insert := func(organizationID uuid.UUID, status string, age time.Duration) uuid.UUID {
		t.Helper()
		event, id := uuid.New(), uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type, ip)
			VALUES ($1, $2, 'system', 'organization.updated', 'organization', '203.0.113.7')`, event, organizationID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO audit.anomalies (id, organization_id, event_id, score, status, created_at)
			VALUES ($1, $2, $3, 0.9, $4, NOW() - $5::interval)`, id, organizationID, event, status, age.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	newest := insert(organization, "open", time.Minute)
	resolved := insert(organization, "resolved", 2*time.Minute)
	oldest := insert(organization, "open", 3*time.Minute)
	insert(other, "open", time.Second)

	ids := func(status string, limit int, after paging.Cursor) ([]uuid.UUID, string) {
		t.Helper()
		list, next, err := svc.ListPage(ctx, organization, status, limit, after)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]uuid.UUID, 0, len(list))
		for _, a := range list {
			if a.IP == nil || *a.IP != "203.0.113.7" {
				t.Errorf("anomaly %s: IP %v, want its event's", a.ID, a.IP)
			}
			out = append(out, a.ID)
		}
		return out, next
	}
	for status, want := range map[string][]uuid.UUID{
		"":         {newest, resolved, oldest},
		"open":     {newest, oldest},
		"resolved": {resolved},
	} {
		if got, next := ids(status, 50, paging.Cursor{}); !slices.Equal(got, want) || next != "" {
			t.Errorf("status %q: %v (next %q), want %v on one page", status, got, next, want)
		}
	}
	first, next := ids("open", 1, paging.Cursor{})
	at, id, err := paging.DecodeTimeUUID(next)
	if err != nil || !slices.Equal(first, []uuid.UUID{newest}) {
		t.Fatalf("first open page: %v, cursor %q (%v); want the newest", first, next, err)
	}
	if rest, _ := ids("open", 1, paging.Cursor{Set: true, Time: at, ID: id}); !slices.Equal(rest, []uuid.UUID{oldest}) {
		t.Errorf("second open page: %v, want the oldest open one", rest)
	}
}
