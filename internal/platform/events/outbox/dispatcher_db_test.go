//go:build integration

package outbox

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// recordingPublisher counts the publishes of each event, failing them all
// while down is set.
type recordingPublisher struct {
	mu    sync.Mutex
	seen  map[uuid.UUID]int
	total int
	down  bool
}

func (p *recordingPublisher) Publish(_ context.Context, m Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[uuid.UUID]int{}
	}
	p.seen[m.ID]++
	p.total++
	if p.down {
		return errors.New("publisher down")
	}
	return nil
}

// enqueue adds n events of eventType to the outbox, deleted again when t ends,
// and returns their IDs.
func enqueue(t *testing.T, n int, eventType string) []uuid.UUID {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	rows, err := pool.Query(ctx, `
		INSERT INTO platform.outbox (aggregate_id, topic, event_type, payload)
		SELECT gen_random_uuid(), 'test.events', $1, '{}' FROM generate_series(1, $2)
		RETURNING id`, eventType, n)
	if err != nil {
		t.Fatal(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform.outbox WHERE event_type = $1`, eventType)
	})
	return ids
}

// TestDispatcherDrainsABacklog checks that a tick keeps publishing batches
// while they come full, within its time budget.
func TestDispatcherDrainsABacklog(t *testing.T) {
	ctx := dbtest.Context(t)
	ids := enqueue(t, 120, "test.backlog")
	pub := &recordingPublisher{}
	d := NewDispatcher(dbtest.Pool(t), pub, time.Second, 50)

	d.budget = 0
	if err := d.drain(ctx); err != nil {
		t.Fatal(err)
	}
	if pub.total != 50 {
		t.Errorf("with no time to spare a tick published %d events, want one batch of 50", pub.total)
	}
	d.budget = drainBudget
	if err := d.drain(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if pub.seen[id] != 1 {
			t.Errorf("event %s published %d times, want once", id, pub.seen[id])
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE id = ANY($1) AND published_at IS NULL`, ids); n != 0 {
		t.Errorf("%d events left unpublished after a tick, want none", n)
	}
}

// TestDispatcherStopsAtAFailingBatch checks that a tick stops after a batch
// with a failure, so an outage isn't hammered, and dead-letters nothing.
func TestDispatcherStopsAtAFailingBatch(t *testing.T) {
	ctx := dbtest.Context(t)
	ids := enqueue(t, 120, "test.outage")
	pub := &recordingPublisher{down: true}
	if err := NewDispatcher(dbtest.Pool(t), pub, time.Second, 50).drain(ctx); err != nil {
		t.Fatal(err)
	}
	if pub.total != 50 {
		t.Errorf("a tick tried %d publishes with the publisher down, want one batch of 50", pub.total)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE id = ANY($1) AND attempts = 1`, ids); n != 50 {
		t.Errorf("%d events have one failed attempt, want 50", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox_dead_letter WHERE id = ANY($1)`, ids); n != 0 {
		t.Errorf("%d events dead-lettered after one failure, want none", n)
	}
}

// TestDispatcherDeadLettersAfterADay checks that an event is dead-lettered
// only once its retries have spanned a day, and counted when it is.
func TestDispatcherDeadLettersAfterADay(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	ids := enqueue(t, 2, "test.dead")
	lastTry, earlyFailure := ids[0], ids[1]
	for id, attempts := range map[uuid.UUID]int{lastTry: DefaultMaxAttempts - 1, earlyFailure: 10} {
		if _, err := pool.Exec(ctx, `
			UPDATE platform.outbox SET attempts = $2, last_attempt_at = NOW() - interval '1 hour' WHERE id = $1`,
			id, attempts); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform.outbox_dead_letter WHERE event_type = 'test.dead'`)
	})
	before := counterValue(t, deadLettered)
	if err := NewDispatcher(pool, &recordingPublisher{down: true}, time.Second, 50).drain(ctx); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox_dead_letter WHERE id = $1 AND attempts = $2`, lastTry, DefaultMaxAttempts); n != 1 {
		t.Errorf("an event failing its last attempt: %d dead letters, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE id = $1 AND attempts = 11`, earlyFailure); n != 1 {
		t.Errorf("an event failing its 11th attempt left the outbox (%d rows), want it kept for retry", n)
	}
	if got := counterValue(t, deadLettered) - before; got != 1 {
		t.Errorf("outbox_dead_lettered_total rose by %v, want 1", got)
	}
}

// counterValue is c's current value.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	return families[0].GetMetric()[0].GetCounter().GetValue()
}

// deadLetter adds a dead letter of eventType, dead-lettered at at, deleted
// again when t ends.
func deadLetter(t *testing.T, eventType string, at time.Time) uuid.UUID {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	id := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO platform.outbox_dead_letter
		    (id, aggregate_id, topic, event_type, payload, created_at, attempts, last_error, dead_lettered_at)
		VALUES ($1, gen_random_uuid(), 'test.events', $2, '{"n": 1}', $3::timestamptz - interval '1 day', $4, 'publisher down', $3)`,
		id, eventType, at, DefaultMaxAttempts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform.outbox_dead_letter WHERE id = $1`, id)
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform.outbox WHERE id = $1`, id)
	})
	return id
}

// TestReplayDeadLetters checks that a replay moves the dead letters it picks,
// and only those, back to the outbox as new events, batch by batch.
func TestReplayDeadLetters(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	picked, other := "test.replay."+uuid.NewString(), "test.replay-other."+uuid.NewString()
	now := time.Now()
	old := deadLetter(t, picked, now.Add(-48*time.Hour))
	recent := deadLetter(t, picked, now.Add(-time.Hour))
	otherType := deadLetter(t, other, now.Add(-time.Hour))

	n, err := ReplayDeadLetters(ctx, pool, ReplayFilter{EventType: picked, Since: now.Add(-24 * time.Hour)})
	if err != nil || n != 1 {
		t.Fatalf("replay of one type since yesterday: %d, %v; want 1", n, err)
	}
	if got := dbtest.Count(t, `
		SELECT count(*) FROM platform.outbox
		WHERE id = $1 AND attempts = 0 AND published_at IS NULL AND last_error IS NULL
		  AND payload = '{"n": 1}' AND created_at < NOW() - interval '1 day'`, recent); got != 1 {
		t.Errorf("the replayed event is not in the outbox as new with its payload and age (%d rows)", got)
	}
	for id, want := range map[uuid.UUID]int{recent: 0, old: 1, otherType: 1} {
		if got := dbtest.Count(t, `SELECT count(*) FROM platform.outbox_dead_letter WHERE id = $1`, id); got != want {
			t.Errorf("dead letter %s: %d rows left, want %d", id, got, want)
		}
	}

	purgeBatch = 1
	t.Cleanup(func() { purgeBatch = 5000 })
	deadLetter(t, other, now)
	if n, err := ReplayDeadLetters(ctx, pool, ReplayFilter{EventType: other}); err != nil || n != 2 {
		t.Errorf("replay of every %s in batches of one: %d, %v; want 2", other, n, err)
	}
}

// TestPurgeDeadLettersKeepsThemNinetyDays checks that the cleanup deletes
// only dead letters older than DeadLetterRetention.
func TestPurgeDeadLettersKeepsThemNinetyDays(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	day := 24 * time.Hour
	expired := deadLetter(t, "test.purge-dead", time.Now().Add(-DeadLetterRetention-day))
	kept := deadLetter(t, "test.purge-dead", time.Now().Add(-DeadLetterRetention+day))
	if _, err := PurgeDeadLetters(ctx, pool, DeadLetterRetention); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[uuid.UUID]int{expired: 0, kept: 1} {
		if got := dbtest.Count(t, `SELECT count(*) FROM platform.outbox_dead_letter WHERE id = $1`, id); got != want {
			t.Errorf("dead letter %s: %d rows left, want %d", id, got, want)
		}
	}
}
