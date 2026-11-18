package activity

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/sse"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// streamRecheck is how long a stream may go on delivering after its reader
// lost access.
const streamRecheck = 30 * time.Second

// maxReplayRows bounds how much of the audit log one connection replays. A
// client further behind gets the cursor of the last row read and a reconnect
// hint, and its next connection carries on from there.
var maxReplayRows = 1000

// replayPage is how many audit rows one replay query reads, as
// ReplayActivityHistory's LIMIT.
const replayPage = 100

// stream serves GET /v1/activity/stream as Server-Sent Events of the audit
// records themselves, each with its own id, so a live event can be opened and
// related as a historical one. It replays the records newer than
// Last-Event-ID, then follows the audit log, every streamPoll or as soon as
// the hub says the organization did something, until the client disconnects,
// the hub shuts down, the reader's credential expires or Access refuses them;
// the query filters apply throughout. Delivery is at least once: a frame's
// cursor is set back streamLag, so a reconnect may resend a record, and when
// the client is too far behind, or the hub couldn't keep up with it, the
// stream ends with a reconnect hint so the next connection catches up.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request) {
	organizationID, _, ok := h.requireOrganizationUser(w, r)
	if !ok {
		return
	}
	reader := httpx.PrincipalFromCtx(r.Context())

	f := StreamFilter{
		Types:    strutil.SplitList(r.URL.Query().Get("types")),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
	}

	// The stream stays open for up to an hour, past HTTP_WRITE_TIMEOUT.
	out := sse.Open(w, time.Hour)
	if out == nil {
		httpx.WriteError(w, r, errs.ErrInternalServer.WithDetail("streaming not supported"))
		return
	}
	// Keep-alive pings every 20s prevent proxy timeouts on idle connections.
	defer out.KeepAlive(20 * time.Second)()

	ctx := r.Context()
	select {
	case <-h.Hub.stopping:
		out.Retry(shutdownRetry)
		return
	default:
	}

	// Subscribe before replaying, so the organization's activity during the
	// replay wakes the tail at once rather than at the next poll.
	evCh, lost, unsub := h.Hub.subscribe(organizationID)
	defer unsub()

	// On reconnect the client sends the ID of the last event it received; replay
	// everything newer before following the log. Without one, the stream
	// starts at the time it was opened.
	tail := newAuditTail(time.Now().UTC())
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		if !h.replayHistory(ctx, out, organizationID, lastID, f, tail) {
			out.Retry(shutdownRetry)
			return
		}
	}

	recheck := time.NewTicker(h.recheckEvery())
	defer recheck.Stop()
	poll := time.NewTicker(streamPoll)
	defer poll.Stop()
	var expired <-chan time.Time
	if reader != nil && reader.ExpiresAt != nil {
		t := time.NewTimer(time.Until(*reader.ExpiresAt))
		defer t.Stop()
		expired = t.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.Hub.stopping:
			out.Retry(shutdownRetry)
			return
		case <-expired:
			return
		case <-recheck.C:
			if !h.stillAllowed(ctx, reader) {
				return
			}
		case <-lost:
			out.Retry(shutdownRetry)
			return
		case <-evCh:
			if !h.followLog(ctx, out, organizationID, tail, f) {
				out.Retry(shutdownRetry)
				return
			}
		case <-poll.C:
			if !h.followLog(ctx, out, organizationID, tail, f) {
				out.Retry(shutdownRetry)
				return
			}
		}
	}
}

// streamPoll is how often a stream reads the audit log when nothing wakes it
// sooner.
const streamPoll = 2 * time.Second

// auditTail is where a stream has read the audit log to: every record after
// (floor, floorID), what the client already had, is sent once, and each sent
// within streamLag of the newest is remembered, as a record committed late can
// still appear among them.
type auditTail struct {
	floor   time.Time
	floorID uuid.UUID
	newest  time.Time
	sent    map[uuid.UUID]time.Time
}

func newAuditTail(from time.Time) *auditTail {
	return &auditTail{floor: from, newest: from, sent: map[uuid.UUID]time.Time{}}
}

// followLog sends the organization's audit records the tail hasn't, oldest first,
// reading back streamLag before the newest it sent. It reports false when the
// log can't be read.
func (h *Handler) followLog(ctx context.Context, out *sse.Writer, organizationID uuid.UUID, t *auditTail, f StreamFilter) bool {
	q := dbgen.New(h.pool)
	afterTs, afterID := t.newest.Add(-streamLag), uuid.Nil
	if !afterTs.After(t.floor) {
		afterTs, afterID = t.floor, t.floorID
	}
	for {
		rows, err := q.ReplayActivityHistory(ctx, dbgen.ReplayActivityHistoryParams{
			OrganizationID: &organizationID,
			AfterTs:        afterTs,
			AfterID:        afterID,
		})
		if err != nil {
			slog.Warn("activity: follow the audit log", "err", err)
			return false
		}
		for _, row := range rows {
			afterTs, afterID = row.CreatedAt, row.ID
			if _, done := t.sent[row.ID]; done {
				continue
			}
			t.sent[row.ID] = row.CreatedAt
			if row.CreatedAt.After(t.newest) {
				t.newest = row.CreatedAt
			}
			if ev := mapAuditRow(toAuditRow(row)); matchesStreamFilter(ev, f) {
				sendActivity(out, ev, row.CreatedAt.Add(-streamLag))
			}
		}
		if len(rows) < replayPage {
			break
		}
	}
	for id, at := range t.sent {
		if at.Before(t.newest.Add(-streamLag)) {
			delete(t.sent, id)
		}
	}
	return true
}

// shutdownRetry is how long the client of a stopping server waits before it
// reconnects, sending its Last-Event-ID so it misses nothing.
const shutdownRetry = 3 * time.Second

// streamLag is how long after its time an audit record may become visible: its
// transaction commits after the record is stamped. The tail reads back this
// far, and a live frame's cursor is set back by it, so a reconnect misses
// nothing; a record may arrive twice, but none is skipped.
const streamLag = 10 * time.Second

// recheckEvery is how often a stream asks Access again.
func (h *Handler) recheckEvery() time.Duration {
	if h.RecheckEvery > 0 {
		return h.RecheckEvery
	}
	return streamRecheck
}

// stillAllowed reports whether reader may go on reading, failing closed when
// Access can't say.
func (h *Handler) stillAllowed(ctx context.Context, reader *httpx.Principal) bool {
	if h.Access == nil {
		return true
	}
	ok, err := h.Access(ctx, reader)
	if err != nil {
		slog.Warn("activity: stream access check failed; ending the stream", "err", err)
		return false
	}
	return ok
}

// replayHistory sends the audit events newer than the lastEventID cursor,
// oldest first, as a connected client would have seen them, page after page
// until it has caught up, and has t follow on from them. It reads at most
// maxReplayRows: further behind, it sends the cursor of the last row read and
// reports false, for the stream to end and the client to carry on from there.
// The cursor of a row the filters pass over is sent too, so a filtered backlog
// is read only once. A lastEventID that does not decode skips the replay, so
// the stream just starts live.
func (h *Handler) replayHistory(ctx context.Context, out *sse.Writer, organizationID uuid.UUID, lastEventID string, f StreamFilter, t *auditTail) bool {
	afterTs, afterID, err := paging.DecodeTimeUUID(lastEventID)
	if err != nil {
		return true // invalid Last-Event-ID — skip replay rather than erroring
	}
	t.floor, t.floorID, t.newest = afterTs, afterID, afterTs
	q := dbgen.New(h.pool)
	for read := 0; ; {
		rows, err := q.ReplayActivityHistory(ctx, dbgen.ReplayActivityHistoryParams{
			OrganizationID: &organizationID,
			AfterTs:        afterTs,
			AfterID:        afterID,
		})
		if err != nil {
			slog.Warn("activity: replay query", "err", err)
			return false
		}
		sentLast := false
		for _, row := range rows {
			ev := mapAuditRow(toAuditRow(row))
			afterTs, afterID, sentLast = row.CreatedAt, row.ID, false
			t.sent[row.ID] = row.CreatedAt
			if row.CreatedAt.After(t.newest) {
				t.newest = row.CreatedAt
			}
			if matchesStreamFilter(ev, f) {
				sendActivity(out, ev, ev.At)
				sentLast = true
			}
		}
		if len(rows) > 0 && !sentLast {
			out.ID(paging.EncodeTimeUUID(afterTs, afterID))
		}
		read += len(rows)
		if len(rows) < replayPage {
			return true
		}
		if read >= maxReplayRows {
			return false
		}
	}
}

// sendActivity writes ev as an "activity" event whose id is the cursor of the
// event at cursorAt, which a reconnecting client sends back as Last-Event-ID.
func sendActivity(out *sse.Writer, ev ActivityEvent, cursorAt time.Time) {
	out.SendWithID(paging.EncodeTimeUUID(cursorAt, ev.ID), "activity", ev)
}
