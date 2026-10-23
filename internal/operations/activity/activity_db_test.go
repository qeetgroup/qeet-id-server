//go:build integration

package activity

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
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

// insertEvent writes an audit event for tenant at the given time.
func insertEvent(t *testing.T, tenant uuid.UUID, action string, at time.Time) auditEvent {
	t.Helper()
	e := auditEvent{id: uuid.New(), at: at.UTC().Truncate(time.Microsecond)}
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO audit.events (id, tenant_id, actor_type, action, resource_type, created_at)
		VALUES ($1, $2, 'system', $3, 'user', $4)
	`, e.id, tenant, action, e.at); err != nil {
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

// TestHistoryPagesThroughEveryEvent checks that following next_cursor returns
// each event exactly once, in order, including events that share a time.
func TestHistoryPagesThroughEveryEvent(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	var events []auditEvent
	for i := range 8 {
		at := base.Add(time.Duration(i) * time.Second)
		if i < 4 {
			at = base // a run of events at one time spans a page boundary
		}
		events = append(events, insertEvent(t, tenant, "user.updated", at))
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
	if got, want := allPages(t, h, "limit=3"), newestFirst(events); !slices.Equal(got, want) {
		t.Errorf("paged history = %v\nwant %v", got, want)
	}
}

// TestFilteredHistoryReachesOlderMatches checks that a severity filter which
// matches nothing in the newest rows still pages on to older matching events.
func TestFilteredHistoryReachesOlderMatches(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	var warnings []auditEvent
	for i := range 2 {
		warnings = append(warnings, insertEvent(t, tenant, "user.deleted", base.Add(time.Duration(i)*time.Second)))
	}
	for i := range 10 {
		insertEvent(t, tenant, "user.created", base.Add(time.Minute+time.Duration(i)*time.Second))
	}

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
	if got, want := allPages(t, h, "limit=1&severity=warning"), newestFirst(warnings); !slices.Equal(got, want) {
		t.Errorf("filtered history = %v, want %v", got, want)
	}
}

// TestStreamReplaysEventsAfterLastEventID checks that a stream opened with
// Last-Event-ID first replays the tenant's newer events, oldest first, each
// with an id a later reconnect can resume from.
func TestStreamReplaysEventsAfterLastEventID(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, tenant, "user.created", base)
	missed := []auditEvent{
		insertEvent(t, tenant, "user.updated", base.Add(time.Second)),
		insertEvent(t, tenant, "user.deleted", base.Add(2*time.Second)),
	}
	insertEvent(t, other, "user.created", base.Add(time.Second))

	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()
	ctx, cancel := context.WithCancel(dbtest.Context(t))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/activity/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Last-Event-ID", encodeCursor(seen.at, seen.id))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open stream: status %d", resp.StatusCode)
	}

	var replayed []uuid.UUID
	scanner := bufio.NewScanner(resp.Body)
	for len(replayed) < len(missed) && scanner.Scan() {
		cursor, ok := strings.CutPrefix(scanner.Text(), "id: ")
		if !ok {
			continue
		}
		_, id, err := decodeCursor(cursor)
		if err != nil {
			t.Fatalf("frame id %q: %v", cursor, err)
		}
		replayed = append(replayed, id)
	}
	if want := []uuid.UUID{missed[0].id, missed[1].id}; !slices.Equal(replayed, want) {
		t.Errorf("replayed %v, want %v", replayed, want)
	}
}

// TestStreamKeepsLiveEventsDuringReplay checks that a live event published
// while the stream is still replaying history is sent after the replay rather
// than lost. The replay is held back by a lock on the audit log.
func TestStreamKeepsLiveEventsDuringReplay(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, tenant, "user.created", base)
	missed := insertEvent(t, tenant, "user.updated", base.Add(time.Second))

	lock, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err := lock.Exec(ctx, `LOCK TABLE audit.events IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock the audit log: %v", err)
	}

	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL+"/activity/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Last-Event-ID", encodeCursor(seen.at, seen.id))
	sent := make(chan []uuid.UUID, 1) // the ids of the first two frames
	go func() {
		var ids []uuid.UUID
		defer func() { sent <- ids }()
		resp, err := srv.Client().Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for len(ids) < 2 && scanner.Scan() {
			if cursor, ok := strings.CutPrefix(scanner.Text(), "id: "); ok {
				if _, id, err := decodeCursor(cursor); err == nil {
					ids = append(ids, id)
				}
			}
		}
	}()

	// Wait until the stream has subscribed while its replay is blocked.
	subscribed := false
	for deadline := time.Now().Add(5 * time.Second); !subscribed && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		subscribed = len(hub.subs[tenant]) == 1
		hub.mu.RUnlock()
	}
	live := newTestEvent("user.deleted", SeverityWarning)
	live.TenantID = tenant
	hub.fanOut(tenant, live)
	if err := lock.Rollback(ctx); err != nil {
		t.Fatalf("unlock the audit log: %v", err)
	}
	if !subscribed {
		t.Fatal("the stream did not subscribe before its replay finished")
	}

	if got, want := <-sent, []uuid.UUID{missed.id, live.ID}; !slices.Equal(got, want) {
		t.Errorf("stream sent %v, want the replayed %s then the live %s", got, missed.id, live.ID)
	}
}

// TestReconnectReplaysEventsTheOutboxHadNotPublished checks that reconnecting
// with a live frame's id replays an audit event recorded shortly before that
// live event arrived, whose own outbox message had yet to be published.
func TestReconnectReplaysEventsTheOutboxHadNotPublished(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()
	// firstFrame opens the stream with lastEventID and returns its first frame's id.
	firstFrame := func(lastEventID string, publish func()) string {
		ctx, cancel := context.WithCancel(dbtest.Context(t))
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/activity/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		if lastEventID != "" {
			req.Header.Set("Last-Event-ID", lastEventID)
		}
		frame := make(chan string, 1)
		go func() {
			defer close(frame)
			resp, err := srv.Client().Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				if cursor, ok := strings.CutPrefix(scanner.Text(), "id: "); ok {
					frame <- cursor
					return
				}
			}
		}()
		if publish != nil {
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				hub.mu.RLock()
				n := len(hub.subs[tenant])
				hub.mu.RUnlock()
				if n == 1 {
					break
				}
			}
			publish()
		}
		select {
		case cursor := <-frame:
			return cursor
		case <-time.After(5 * time.Second):
			t.Fatal("no frame")
			return ""
		}
	}

	live := newTestEvent("user.updated", SeverityInfo)
	live.TenantID, live.At = tenant, time.Now().UTC()
	liveID := firstFrame("", func() { hub.fanOut(tenant, live) })
	lagged := insertEvent(t, tenant, "user.created", live.At.Add(-3*time.Second))

	cursor := firstFrame(liveID, nil)
	if _, id, err := decodeCursor(cursor); err != nil || id != lagged.id {
		t.Errorf("reconnecting replayed %q (%v), want the lagged event %s", cursor, err, lagged.id)
	}
}
