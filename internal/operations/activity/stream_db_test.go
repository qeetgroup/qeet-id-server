//go:build integration

package activity

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// TestStreamReplaysEventsAfterLastEventID checks that a stream opened with
// Last-Event-ID first replays the organization's newer events, oldest first, each
// with an id a later reconnect can resume from.
func TestStreamReplaysEventsAfterLastEventID(t *testing.T) {
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, organization, "user.created", base)
	missed := []auditEvent{
		insertEvent(t, organization, "user.updated", base.Add(time.Second)),
		insertEvent(t, organization, "user.deleted", base.Add(2*time.Second)),
	}
	insertEvent(t, other, "user.created", base.Add(time.Second))

	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()
	ctx, cancel := context.WithCancel(dbtest.Context(t))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/activity/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Last-Event-ID", paging.EncodeTimeUUID(seen.at, seen.id))
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
		_, id, err := paging.DecodeTimeUUID(cursor)
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
				if _, id, err := paging.DecodeTimeUUID(cursor); err == nil {
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
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, organization, "user.created", base)
	missed := insertEvent(t, organization, "user.updated", base.Add(time.Second))
	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()

	frames, stop := streamFrames(t, srv, paging.EncodeTimeUUID(seen.at, seen.id))
	defer stop()
	if f := nextFrame(t, frames); f[0] != missed.id.String() {
		t.Fatalf("first frame %s, want the replayed %s", f[0], missed.id)
	}
	live := insertEvent(t, organization, "user.deleted", time.Now())
	hub.fanOut(organization, newTestEvent("user.deleted", SeverityWarning)) // the outbox's word wakes the stream
	if f := nextFrame(t, frames); f[0] != live.id.String() {
		t.Fatalf("live frame %s, want the audit record %s", f[0], live.id)
	}
	late := insertEvent(t, organization, "user.updated", live.at.Add(-3*time.Second)) // committed after a later one
	next := insertEvent(t, organization, "group.created", time.Now())
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
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	hub := NewHub(nil)
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), hub).Mount))
	defer srv.Close()

	frames, stop := streamFrames(t, srv, "")
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		n := len(hub.subs[organization])
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
	}
	time.Sleep(50 * time.Millisecond) // the stream starts following from when it opened
	live := insertEvent(t, organization, "user.updated", time.Now())
	frame := nextFrame(t, frames)
	stop()
	if frame[0] != live.id.String() {
		t.Fatalf("live frame %s, want %s", frame[0], live.id)
	}
	lagged := insertEvent(t, organization, "user.created", live.at.Add(-3*time.Second))

	frames, stop = streamFrames(t, srv, frame[1])
	defer stop()
	if f := nextFrame(t, frames); f[0] != lagged.id.String() {
		t.Errorf("reconnecting replayed %s, want the lagged record %s", f[0], lagged.id)
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
			_, id, err := paging.DecodeTimeUUID(cursor)
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
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, organization, "user.created", base)
	var missed []uuid.UUID
	for i := range 151 {
		missed = append(missed, insertEvent(t, organization, "user.updated", base.Add(time.Duration(i+1)*time.Millisecond)).id)
	}
	wanted := insertEvent(t, organization, "user.deleted", base.Add(time.Second))
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()

	ids, _, reconnect := replayed(t, srv, "/activity/stream", paging.EncodeTimeUUID(seen.at, seen.id), 152)
	if reconnect || len(ids) != 152 || !slices.Equal(ids[:151], missed) || ids[151] != wanted.id {
		t.Errorf("replay of 152 missed events: %d replayed, reconnect %v; want all of them, oldest first", len(ids), reconnect)
	}
	ids, _, reconnect = replayed(t, srv, "/activity/stream?types=user.deleted", paging.EncodeTimeUUID(seen.at, seen.id), 1)
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
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	base := time.Now().Add(-time.Hour)
	seen := insertEvent(t, organization, "user.created", base)
	var missed []uuid.UUID
	for i := range 250 {
		missed = append(missed, insertEvent(t, organization, "user.updated", base.Add(time.Duration(i+1)*time.Millisecond)).id)
	}
	srv := httptest.NewServer(dbtest.Serve(dbtest.Principal(admin.ID, organization), NewHandler(dbtest.Pool(t), NewHub(nil)).Mount))
	defer srv.Close()

	var all []uuid.UUID
	cursor := paging.EncodeTimeUUID(seen.at, seen.id)
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
	cursor = paging.EncodeTimeUUID(seen.at, seen.id)
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
