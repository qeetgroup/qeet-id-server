//go:build integration

package outbox

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestPurgePublishedKeepsPendingEvents checks that the purge deletes, batch by
// batch, only events published before the retention, never one still to be
// delivered.
func TestPurgePublishedKeepsPendingEvents(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	aggregate := uuid.New()
	insert := func(publishedAt any) uuid.UUID {
		id := uuid.New()
		if _, err := pool.Exec(ctx, `
			INSERT INTO platform.outbox (id, aggregate_id, topic, event_type, payload, published_at)
			VALUES ($1, $2, 'test.events', 'test.purge', '{}', $3)
		`, id, aggregate, publishedAt); err != nil {
			t.Fatal(err)
		}
		return id
	}
	purgeBatch = 2
	t.Cleanup(func() { purgeBatch = 5000 })
	want := map[uuid.UUID]int{}
	for range 5 {
		want[insert(time.Now().Add(-PublishedRetention-time.Hour))] = 0
	}
	want[insert(time.Now().Add(-time.Hour))] = 1
	want[insert(nil)] = 1

	n, err := PurgePublished(ctx, pool, PublishedRetention)
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Errorf("purged %d events in batches of %d, want at least the 5 old ones", n, purgeBatch)
	}
	for id, want := range want {
		if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE id = $1`, id); n != want {
			t.Errorf("event %s: %d rows left, want %d", id, n, want)
		}
	}
}
