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
	if got, want := allPages(t, h, "limit=1&min_severity=warning"), newestFirst(warnings); !slices.Equal(got, want) {
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

// streamFrames opens the stream with lastEventID and returns a channel of the
// ids and cursors of its frames, in order, and a stop for the stream.
func streamFrames(t *testing.T, srv *httptest.Server, lastEventID string) (<-chan [2]string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(dbtest.Context(t))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/activity/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	frames := make(chan [2]string, 16)
	go func() {
		defer close(frames)
		resp, err := srv.Client().Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			if cursor, ok := strings.CutPrefix(scanner.Text(), "id: "); ok {
				if _, id, err := decodeCursor(cursor); err == nil {
					frames <- [2]string{id.String(), cursor}
				}
			}
		}
	}()
	return frames, cancel
}

// nextFrame waits for the stream's next frame.
func nextFrame(t *testing.T, frames <-chan [2]string) [2]string {
	t.Helper()
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatal("the stream ended")
		}
		return f
	case <-time.After(10 * time.Second):
		t.Fatal("no frame")
		return [2]string{}
	}
}

// TestLiveFramesAreTheAuditRecords checks that after replaying what a client
// missed, the stream sends each new audit record once, as itself, with its own
// id, whether the hub wakes it or its poll does, a record committed late
// included.
func TestLiveFramesAreTheAuditRecords(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, tenant, "user.created", base)
	missed := insertEvent(t, tenant, "user.updated", base.Add(time.Second))
	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()

	frames, stop := streamFrames(t, srv, encodeCursor(seen.at, seen.id))
	defer stop()
	if f := nextFrame(t, frames); f[0] != missed.id.String() {
		t.Fatalf("first frame %s, want the replayed %s", f[0], missed.id)
	}
	live := insertEvent(t, tenant, "user.deleted", time.Now())
	hub.fanOut(tenant, newTestEvent("user.deleted", SeverityWarning)) // the outbox's word wakes the stream
	if f := nextFrame(t, frames); f[0] != live.id.String() {
		t.Fatalf("live frame %s, want the audit record %s", f[0], live.id)
	}
	late := insertEvent(t, tenant, "user.updated", live.at.Add(-3*time.Second)) // committed after a later one
	next := insertEvent(t, tenant, "group.created", time.Now())
	got := []string{nextFrame(t, frames)[0], nextFrame(t, frames)[0]}
	slices.Sort(got)
	want := []string{late.id.String(), next.id.String()}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("frames %v, want the late record and the next, once each", got)
	}
	select {
	case f := <-frames:
		t.Errorf("a record sent again: %s", f[0])
	case <-time.After(2*streamPoll + time.Second):
	}
}

// TestReconnectReplaysRecordsCommittedLate checks that reconnecting with a
// live frame's id replays an audit record stamped shortly before it but
// committed after it was sent.
func TestReconnectReplaysRecordsCommittedLate(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()

	frames, stop := streamFrames(t, srv, "")
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		n := len(hub.subs[tenant])
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
	}
	time.Sleep(50 * time.Millisecond) // the stream starts following from when it opened
	live := insertEvent(t, tenant, "user.updated", time.Now())
	frame := nextFrame(t, frames)
	stop()
	if frame[0] != live.id.String() {
		t.Fatalf("live frame %s, want %s", frame[0], live.id)
	}
	lagged := insertEvent(t, tenant, "user.created", live.at.Add(-3*time.Second))

	frames, stop = streamFrames(t, srv, frame[1])
	defer stop()
	if f := nextFrame(t, frames); f[0] != lagged.id.String() {
		t.Errorf("reconnecting replayed %s, want the lagged record %s", f[0], lagged.id)
	}
}

// TestSubjectIncludesEventsNamingThePerson checks that a person's timeline and
// summary include events about another resource that name them in
// metadata.user_id, such as being added to a group, and not someone else's.
func TestSubjectIncludesEventsNamingThePerson(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin, person, other := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	insert := func(userID string) uuid.UUID {
		id := uuid.New()
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
			INSERT INTO audit.events (id, tenant_id, actor_user_id, actor_type, action, resource_type, resource_id, metadata, created_at)
			VALUES ($1, $2, $3, 'user', 'group.member_added', 'group', $4, jsonb_build_object('user_id', $5::text), $6)
		`, id, tenant, admin.ID, uuid.New(), userID, at); err != nil {
			t.Fatal(err)
		}
		return id
	}
	added := insert(person.ID.String())
	insert(other.ID.String())
	insert("not-a-uuid") // a malformed value doesn't break the filter

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
	if got := allPages(t, h, "subject="+person.ID.String()); !slices.Equal(got, []uuid.UUID{added}) {
		t.Errorf("the person's timeline = %v, want their group membership %v", got, added)
	}
	var summary struct {
		Total int64 `json:"total"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/activity/summary?subject="+person.ID.String(), nil), &summary)
	if summary.Total != 1 {
		t.Errorf("the person's summary counts %d events, want 1", summary.Total)
	}
}

// TestOneEventByID checks that an organisation's event is fetched by its id
// with its metadata, and that another organisation's id answers 404.
func TestOneEventByID(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	mine, theirs := uuid.New(), uuid.New()
	for id, owner := range map[uuid.UUID]uuid.UUID{mine: tenant, theirs: other} {
		if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
			INSERT INTO audit.events (id, tenant_id, actor_user_id, actor_type, action, resource_type, user_agent, metadata, created_at)
			VALUES ($1, $2, $3, 'user', 'user.updated', 'user', 'Mozilla/5.0', '{"fields": ["name"]}', NOW())
		`, id, owner, admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount)
	base := "/tenants/" + tenant.String() + "/activity/"

	rec := dbtest.Do(t, h, http.MethodGet, base+mine.String(), nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), mine.String()) || !strings.Contains(rec.Body.String(), `"fields"`) {
		t.Errorf("own event: %d %s, want it with its metadata", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodGet, base+theirs.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation's event: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+other.String()+"/activity/"+theirs.String(), nil); rec.Code != http.StatusForbidden {
		t.Errorf("naming another organisation in the path: %d, want 403", rec.Code)
	}
}

// replayed opens the stream at path with Last-Event-ID lastID and reads it
// until want activity frames arrived or the stream ended. It returns their ids,
// the last cursor the stream gave (an activity frame's or a bare one), and
// whether the stream ended with a reconnect hint.
func replayed(t *testing.T, srv *httptest.Server, path, lastID string, want int) (ids []uuid.UUID, cursor string, reconnect bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(dbtest.Context(t), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Last-Event-ID", lastID)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()
	activity := false
	scanner := bufio.NewScanner(resp.Body)
	for len(ids) < want && scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			cursor = strings.TrimPrefix(line, "id: ")
		case line == "event: activity":
			activity = true
		case strings.HasPrefix(line, "retry: "):
			return ids, cursor, true
		case line == "" && activity:
			_, id, err := decodeCursor(cursor)
			if err != nil {
				t.Fatalf("frame id %q: %v", cursor, err)
			}
			ids = append(ids, id)
			activity = false
		}
	}
	return ids, cursor, false
}

// TestReplayCatchesUpPastOnePage checks that a reconnect replays every event
// it missed, a page of the audit log after another, and that a filtered
// backlog is read through to the events the filter keeps.
func TestReplayCatchesUpPastOnePage(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, tenant, "user.created", base)
	var missed []uuid.UUID
	for i := range 151 {
		missed = append(missed, insertEvent(t, tenant, "user.updated", base.Add(time.Duration(i+1)*time.Millisecond)).id)
	}
	wanted := insertEvent(t, tenant, "user.deleted", base.Add(time.Second))
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()

	ids, _, reconnect := replayed(t, srv, "/activity/stream", encodeCursor(seen.at, seen.id), 152)
	if reconnect || len(ids) != 152 || !slices.Equal(ids[:151], missed) || ids[151] != wanted.id {
		t.Errorf("replay of 152 missed events: %d replayed, reconnect %v; want all of them, oldest first", len(ids), reconnect)
	}
	ids, _, reconnect = replayed(t, srv, "/activity/stream?types=user.deleted", encodeCursor(seen.at, seen.id), 1)
	if reconnect || len(ids) != 1 || ids[0] != wanted.id {
		t.Errorf("filtered replay behind 151 others: %v, reconnect %v; want the one it keeps", ids, reconnect)
	}
}

// TestReplayBeyondItsBoundCarriesOn checks that a connection replays at most
// maxReplayRows, then gives the cursor of the last row it read and a reconnect
// hint, and that reconnecting from there replays the rest: every event once,
// in order, a filtered backlog included.
func TestReplayBeyondItsBoundCarriesOn(t *testing.T) {
	maxReplayRows = 100
	t.Cleanup(func() { maxReplayRows = 1000 })
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, tenant, "user.created", base)
	var missed []uuid.UUID
	for i := range 250 {
		missed = append(missed, insertEvent(t, tenant, "user.updated", base.Add(time.Duration(i+1)*time.Millisecond)).id)
	}
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, tenant), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()

	var all []uuid.UUID
	cursor := encodeCursor(seen.at, seen.id)
	for conn := 1; ; conn++ {
		ids, next, reconnect := replayed(t, srv, "/activity/stream", cursor, len(missed)-len(all))
		all = append(all, ids...)
		if !reconnect {
			break
		}
		if conn > 5 || next == cursor {
			t.Fatalf("connection %d made no progress (cursor %q)", conn, next)
		}
		cursor = next
	}
	if !slices.Equal(all, missed) {
		t.Errorf("replayed %d events over reconnects, want the %d missed, once each and in order", len(all), len(missed))
	}

	// A filtered backlog moves the cursor on too, so reconnects reach the end.
	cursor = encodeCursor(seen.at, seen.id)
	for conn := 1; ; conn++ {
		ids, next, reconnect := replayed(t, srv, "/activity/stream?types=user.deleted", cursor, 1)
		if len(ids) != 0 {
			t.Fatalf("a filtered replay sent %v, want nothing", ids)
		}
		if !reconnect {
			break
		}
		if conn > 5 || next == cursor {
			t.Fatalf("filtered connection %d made no progress (cursor %q)", conn, next)
		}
		cursor = next
	}
}
