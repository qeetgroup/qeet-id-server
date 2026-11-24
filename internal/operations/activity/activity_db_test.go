//go:build integration

package activity

import (
	"bytes"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// auditEvent is an audit row written by insertEvent.
type auditEvent struct {
	id uuid.UUID
	at time.Time
}

// insertEvent writes an audit event for organization at the given time.
func insertEvent(t *testing.T, organization uuid.UUID, action string, at time.Time) auditEvent {
	t.Helper()
	e := auditEvent{id: uuid.New(), at: at.UTC().Truncate(time.Microsecond)}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO audit.events (id, organization_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, 'system', $3, 'user', $4)
	`, e.id, organization, action, e.at); err != nil {
		t.Fatalf("insert %s: %v", action, err)
	}
	return e
}

// newestFirst returns the ids of events in history order: newest first, and by
// descending id within the same time.
func newestFirst(events []auditEvent) []uuid.UUID {
	sorted := slices.Clone(events)
	slices.SortFunc(sorted, func(a, b auditEvent) int {
		if c := b.at.Compare(a.at); c != 0 {
			return c
		}
		return bytes.Compare(b.id[:], a.id[:])
	})
	ids := make([]uuid.UUID, len(sorted))
	for i, e := range sorted {
		ids[i] = e.id
	}
	return ids
}

// allPages follows next_cursor from the first history page to the last and
// returns every event id in the order served.
func allPages(t *testing.T, h http.Handler, query string) []uuid.UUID {
	t.Helper()
	var ids []uuid.UUID
	cursor := ""
	for range 50 {
		path := "/activity?" + query
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		rec := dbtest.Do(t, h, http.MethodGet, path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, body %s", path, rec.Code, rec.Body)
		}
		var page struct {
			Events []struct {
				ID uuid.UUID `json:"id"`
			} `json:"events"`
			NextCursor string `json:"next_cursor"`
		}
		dbtest.Decode(t, rec, &page)
		for _, ev := range page.Events {
			ids = append(ids, ev.ID)
		}
		if page.NextCursor == "" {
			return ids
		}
		cursor = page.NextCursor
	}
	t.Fatal("history did not reach its last page")
	return nil
}
