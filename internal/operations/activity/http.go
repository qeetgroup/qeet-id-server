package activity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the tenant-scoped Live Activity endpoints: the SSE stream,
// history, summary and related events.
type Handler struct {
	Hub  *Hub
	pool *pgxpool.Pool
	// Access decides again, while a stream is open, whether its reader may
	// still read it, as the request was admitted: their session or credential
	// still live and audit.read still theirs. A stream it refuses, or can't
	// ask, ends. nil leaves an open stream unchecked.
	Access func(ctx context.Context, p *httpx.Principal) (bool, error)
	// RecheckEvery is how often Access is asked; 0 means streamRecheck.
	RecheckEvery time.Duration
}

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

// NewHandler returns a Handler that reads history from pool and live events
// from hub.
func NewHandler(pool *pgxpool.Pool, hub *Hub) *Handler {
	return &Handler{pool: pool, Hub: hub}
}

// Mount registers the activity routes. Every route requires the audit.read
// permission.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/activity", h.history)
	r.Get("/activity/summary", h.summary)
	r.Get("/activity/stream", h.stream)
	r.Get("/activity/{id}/related", h.related)
	r.Get("/tenants/{tenantID}/activity/{id}", h.event)
}

// stream serves GET /v1/activity/stream as Server-Sent Events. It replays audit
// events newer than Last-Event-ID, then forwards live hub events until the
// client disconnects, the hub shuts down, the reader's credential expires or
// Access refuses them; the query filters apply to both. Delivery is
// at least once: an event may arrive twice, and when the client is too far
// behind, or the hub couldn't keep up with it, the stream ends with a
// reconnect hint so the next connection catches up from the audit log.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}
	reader := httpx.PrincipalFromCtx(r.Context())

	f := StreamFilter{
		Types:    splitCSV(r.URL.Query().Get("types")),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
	}

	// Extend the write deadline, which HTTP_WRITE_TIMEOUT (30s by default) would
	// otherwise apply to this long-lived stream.
	if rc := http.NewResponseController(w); rc != nil {
		if err := rc.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
			slog.Warn("activity: extend write deadline", "err", err)
		}
	}

	// SSE headers — must be set before the first write.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable Nginx/Caddy proxy buffering

	sse := newSSEWriter(w)
	if sse == nil {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Keep-alive pings every 20s prevent proxy timeouts on idle connections.
	// stopKeepAlive runs first (defers are LIFO), so the goroutine has exited
	// before this handler returns and can never write to a released
	// ResponseWriter.
	donePing := make(chan struct{})
	defer sse.stopKeepAlive()
	defer close(donePing)
	sse.startKeepAlive(donePing, 20*time.Second)

	ctx := r.Context()
	select {
	case <-h.Hub.stopping:
		sse.retryLater()
		return
	default:
	}

	// Subscribe before replaying, so a live event published during the replay
	// waits in the channel instead of being lost. Live events come from the
	// outbox and replayed ones from the audit log, with different ids, so they
	// can't be matched: an event in both may arrive twice, but none is dropped.
	evCh, lost, unsub := h.Hub.subscribe(tenantID)
	defer unsub()

	// On reconnect the client sends the ID of the last event it received; replay
	// everything newer before switching to live.
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		if !h.replayHistory(ctx, sse, tenantID, lastID, f) {
			sse.retryLater()
			return
		}
	}

	recheck := time.NewTicker(h.recheckEvery())
	defer recheck.Stop()
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
			sse.retryLater()
			return
		case <-expired:
			return
		case <-recheck.C:
			if !h.stillAllowed(ctx, reader) {
				return
			}
		case <-lost:
			sse.retryLater()
			return
		case ev := <-evCh:
			// Defence in depth: drop an event whose own TenantID is not the
			// connection's, in case the hub ever mis-routes one.
			if ev.TenantID != tenantID {
				slog.Error("activity: cross-tenant event dropped at write boundary",
					"connection_tenant", tenantID,
					"event_tenant", ev.TenantID)
				continue
			}
			if !matchesStreamFilter(ev, f) {
				continue
			}
			sse.sendActivity(ev, ev.At.Add(-outboxLag))
		}
	}
}

// shutdownRetry is how long the client of a stopping server waits before it
// reconnects, sending its Last-Event-ID so it misses nothing.
const shutdownRetry = 3 * time.Second

// outboxLag is how far a live event may trail the audit record it reports: the
// outbox's poll interval, with margin. A live frame's cursor is set back by it,
// so a reconnect replays what the outbox had yet to publish; an event may
// arrive twice, but none is skipped.
const outboxLag = 10 * time.Second

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
// until it has caught up. It reads at most maxReplayRows: further behind, it
// sends the cursor of the last row read and reports false, for the stream to
// end and the client to carry on from there. The cursor of a row the filters
// pass over is sent too, so a filtered backlog is read only once. A lastEventID
// that does not decode skips the replay, so the stream just starts live.
func (h *Handler) replayHistory(ctx context.Context, sse *sseWriter, tenantID uuid.UUID, lastEventID string, f StreamFilter) bool {
	afterTs, afterID, err := decodeCursor(lastEventID)
	if err != nil {
		return true // invalid Last-Event-ID — skip replay rather than erroring
	}
	q := dbgen.New(h.pool)
	for read := 0; ; {
		rows, err := q.ReplayActivityHistory(ctx, dbgen.ReplayActivityHistoryParams{
			TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
			AfterTs:  afterTs,
			AfterID:  afterID,
		})
		if err != nil {
			slog.Warn("activity: replay query", "err", err)
			return false
		}
		sentLast := false
		for _, row := range rows {
			ev := mapAuditRow(replayRowToAuditRow(row))
			afterTs, afterID, sentLast = row.CreatedAt, row.ID, false
			if matchesStreamFilter(ev, f) {
				sse.sendActivity(ev, ev.At)
				sentLast = true
			}
		}
		if len(rows) > 0 && !sentLast {
			sse.sendCursor(afterTs, afterID)
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

// history serves GET /v1/activity: one cursor-paginated page of events from
// the audit log.
func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cursor := r.URL.Query().Get("cursor")
	f, err := parseListFilter(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	events, next, err := h.listHistory(r.Context(), tenantID, f, cursor, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if events == nil {
		events = []ActivityEvent{}
	}
	total, err := dbgen.New(h.pool).CountActivityHistory(r.Context(), historyCountParams(tenantID, f))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := map[string]any{"events": events, "total": min(total, maxCountedEvents), "total_capped": total > maxCountedEvents}
	if next != "" {
		resp["next_cursor"] = next
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// maxCountedEvents is how far the history's total counts; past it the total
// says it is capped.
const maxCountedEvents = 10000

// historyCountParams are f's filters for CountActivityHistory, counting one
// past maxCountedEvents.
func historyCountParams(tenantID uuid.UUID, f ListFilter) dbgen.CountActivityHistoryParams {
	p := historyParams(tenantID, f)
	return dbgen.CountActivityHistoryParams{
		TenantID: p.TenantID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
		CountCap: maxCountedEvents + 1,
	}
}

// historyParams are f's filters for ListActivityHistory, with no cursor or
// limit. A zero-value pgtype (Valid=false) passes NULL, which the query treats
// as "no filter on this dimension".
func historyParams(tenantID uuid.UUID, f ListFilter) dbgen.ListActivityHistoryParams {
	params := dbgen.ListActivityHistoryParams{
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		Actions:       f.Types, // nil slice → NULL → no filter
		ResourceTypes: f.ResourceTypes,
		Categories:    f.Categories,
		Severities:    f.Severities,
		Ip:            f.IP,
	}
	if f.MinSeverity != "" {
		params.MinSeverity = &f.MinSeverity
	}
	if f.ActorID != uuid.Nil {
		params.ActorID = pgtype.UUID{Bytes: f.ActorID, Valid: true}
	}
	if f.Subject != nil {
		params.Subject = pgtype.UUID{Bytes: *f.Subject, Valid: true}
	}
	if f.ResourceID != nil {
		params.ResourceID = pgtype.UUID{Bytes: *f.ResourceID, Valid: true}
	}
	if f.From != nil {
		params.FromTs = pgtype.Timestamptz{Time: *f.From, Valid: true}
	}
	if f.To != nil {
		params.ToTs = pgtype.Timestamptz{Time: *f.To, Valid: true}
	}
	if f.Search != "" {
		params.Q = &f.Search
	}
	return params
}

// listHistory returns a page of up to limit events (50 when limit is not in
// 1..200) and the next page's cursor, or "" on the last page. Every filter is
// applied in the query, so a page is full unless it is the last.
func (h *Handler) listHistory(ctx context.Context, tenantID uuid.UUID, f ListFilter, cursor string, limit int) ([]ActivityEvent, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	params := historyParams(tenantID, f)
	params.RowLimit = int32(limit + 1) // #nosec G115 -- at most 201
	if cursor != "" {
		cursorTs, cursorID, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		params.CursorTs = pgtype.Timestamptz{Time: cursorTs, Valid: true}
		params.CursorID = pgtype.UUID{Bytes: cursorID, Valid: true}
	}
	dbRows, err := dbgen.New(h.pool).ListActivityHistory(ctx, params)
	if err != nil {
		return nil, "", err
	}
	out := make([]ActivityEvent, 0, len(dbRows))
	for _, row := range dbRows {
		out = append(out, mapAuditRow(listRowToAuditRow(row)))
	}
	var next string
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = encodeCursor(last.At, last.ID)
	}
	return out, next, nil
}

// parseListFilter builds the ListFilter shared by history and summary from the
// query string. Values that do not parse (actor, subject, from, to) are
// ignored; an unknown severity or category, or a malformed resource_id or ip,
// is refused with ErrBadRequest.
func parseListFilter(r *http.Request) (ListFilter, error) {
	query := r.URL.Query()
	f := ListFilter{
		Types:         splitCSV(query.Get("types")),
		Severities:    splitCSV(query.Get("severity")),
		MinSeverity:   query.Get("min_severity"),
		Categories:    splitCSV(query.Get("category")),
		Search:        query.Get("q"),
		ResourceTypes: splitCSV(query.Get("resource_type")),
	}
	for _, s := range append(slices.Clone(f.Severities), f.MinSeverity) {
		if s != "" && !slices.Contains(severities, s) {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("unknown severity " + s)
		}
	}
	for _, c := range f.Categories {
		if !slices.Contains(categories, c) {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("unknown category " + c)
		}
	}
	if raw := query.Get("resource_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid resource_id")
		}
		f.ResourceID = &id
	}
	if raw := query.Get("ip"); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid ip")
		}
		f.IP = &addr
	}
	if raw := r.URL.Query().Get("actor"); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			f.ActorID = id
		}
	}
	if raw := r.URL.Query().Get("subject"); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			f.Subject = &id
		}
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.From = &t
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			f.To = &t
		}
	}
	return f, nil
}

// The severities and categories activity gives an action.
var (
	severities = []string{SeverityInfo, SeveritySuccess, SeverityWarning, SeverityError, SeverityCritical}
	categories = []string{CategoryAuthentication, CategoryAuthorization, CategorySecurity, CategoryDirectory, CategoryDeveloper, CategorySystem}
)

// Summary window and bucket bounds. The window defaults to the last 24h and is
// capped at a year and a day, so the per-tenant aggregates never scan
// unbounded history; a long window gets buckets of up to a week.
const (
	summaryDefaultWindow = 24 * time.Hour
	summaryMaxWindow     = 366 * 24 * time.Hour
	summaryDefaultBucket = int64(3600)
	summaryMinBucket     = int64(60)
	summaryMaxBucket     = int64(7 * 86400)
	summaryTargetBuckets = 48
)

// activitySummaryResponse is the aggregate wire shape for GET /v1/activity/summary.
type activitySummaryResponse struct {
	Total          int64            `json:"total"`
	UniqueActors   int64            `json:"unique_actors"`
	Actors         actorCounts      `json:"actors"`
	SecurityAlerts int64            `json:"security_alerts"`
	BySeverity     map[string]int64 `json:"by_severity"`
	ByCategory     map[string]int64 `json:"by_category"`
	ByOutcome      map[string]int64 `json:"by_outcome"`
	Series         []summaryBucket  `json:"series"`
	BucketSeconds  int64            `json:"bucket_seconds"`
	Window         summaryWindow    `json:"window"`
}

// actorCounts is how many distinct actors of each kind the summary's events
// have: people, API keys, agents and service principals.
type actorCounts struct {
	People   int64 `json:"people"`
	APIKeys  int64 `json:"api_keys"`
	Agents   int64 `json:"agents"`
	Services int64 `json:"services"`
}

// summaryBucket is one time slice of the summary series: Count is every event
// in the slice, and the other fields break it down by outcome or severity.
type summaryBucket struct {
	At       time.Time `json:"at"`
	Count    int64     `json:"count"`
	Success  int64     `json:"success"`
	Warning  int64     `json:"warning"`
	Failed   int64     `json:"failed"`
	Info     int64     `json:"info"`
	Critical int64     `json:"critical"`
}

type summaryWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// summary serves GET /v1/activity/summary: counts by severity, category and
// outcome, plus a time series, under the same filters as history. It ignores the
// severity and category filters, because those are what it reports. The query
// groups by action; severityOf and categoryOf fold the groups in Go.
func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	f, err := parseListFilter(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// The window defaults to the last 24h and is clamped to summaryMaxWindow.
	to := time.Now().UTC()
	if f.To != nil {
		to = f.To.UTC()
	}
	from := to.Add(-summaryDefaultWindow)
	if f.From != nil {
		from = f.From.UTC()
	}
	if to.Sub(from) > summaryMaxWindow {
		from = to.Add(-summaryMaxWindow)
	}
	if !from.Before(to) {
		from = to.Add(-summaryDefaultWindow)
	}
	f.From = &from
	f.To = &to

	// Bucket width: explicit ?bucket= wins (clamped), else aim for ~48 buckets.
	bucket := summaryDefaultBucket
	if raw := r.URL.Query().Get("bucket"); raw != "" {
		if b, errB := strconv.ParseInt(raw, 10, 64); errB == nil && b > 0 {
			bucket = b
		}
	} else {
		span := int64(to.Sub(from).Seconds())
		if span > 0 {
			bucket = span / summaryTargetBuckets
		}
	}
	if bucket < summaryMinBucket {
		bucket = summaryMinBucket
	}
	if bucket > summaryMaxBucket {
		bucket = summaryMaxBucket
	}

	q := dbgen.New(h.pool)
	ctx := r.Context()

	p := historyParams(tenantID, f)
	byAction, err := q.SummarizeActivityByAction(ctx, dbgen.SummarizeActivityByActionParams{
		TenantID: p.TenantID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	totals, err := q.SummarizeActivityTotals(ctx, dbgen.SummarizeActivityTotalsParams{
		TenantID: p.TenantID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	series, err := q.SummarizeActivityTimeSeries(ctx, dbgen.SummarizeActivityTimeSeriesParams{
		BucketSeconds: bucket,
		TenantID:      p.TenantID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	// Zero-fill all buckets so the console renders a stable legend.
	bySeverity := map[string]int64{
		SeverityInfo: 0, SeveritySuccess: 0, SeverityWarning: 0, SeverityError: 0, SeverityCritical: 0,
	}
	byCategory := map[string]int64{
		CategoryAuthentication: 0, CategoryAuthorization: 0, CategorySecurity: 0,
		CategoryDirectory: 0, CategoryDeveloper: 0, CategorySystem: 0,
	}
	byOutcome := map[string]int64{"success": 0, "warning": 0, "failed": 0, "info": 0}
	for _, row := range byAction {
		sev := severityOf(row.Action)
		bySeverity[sev] += row.Count
		byCategory[categoryOf(row.Action)] += row.Count
		byOutcome[outcomeOf(sev)] += row.Count
	}

	// Fold the per-(bucket, action) rows into per-outcome buckets. Rows arrive
	// ordered by bucket, so rows of one bucket are contiguous.
	out := make([]summaryBucket, 0)
	for _, s := range series {
		at := s.Bucket.UTC()
		if len(out) == 0 || !out[len(out)-1].At.Equal(at) {
			out = append(out, summaryBucket{At: at})
		}
		i := len(out) - 1
		sev := severityOf(s.Action)
		out[i].Count += s.Count
		switch outcomeOf(sev) {
		case "success":
			out[i].Success += s.Count
		case "warning":
			out[i].Warning += s.Count
		case "failed":
			out[i].Failed += s.Count
		default:
			out[i].Info += s.Count
		}
		if sev == SeverityCritical {
			out[i].Critical += s.Count
		}
	}

	httpx.WriteJSON(w, http.StatusOK, activitySummaryResponse{
		Total:        totals.Total,
		UniqueActors: totals.UniqueActors,
		Actors: actorCounts{
			People: totals.UniqueActors, APIKeys: totals.UniqueApiKeys,
			Agents: totals.UniqueAgents, Services: totals.UniqueServices,
		},
		SecurityAlerts: bySeverity[SeverityCritical],
		BySeverity:     bySeverity,
		ByCategory:     byCategory,
		ByOutcome:      byOutcome,
		Series:         out,
		BucketSeconds:  bucket,
		Window:         summaryWindow{From: from, To: to},
	})
}

// Related-events window bounds around the anchor event.
const (
	relatedDefaultWindow = 5 * time.Minute
	relatedMinWindow     = 1 * time.Minute
	relatedMaxWindow     = 1 * time.Hour
	relatedRowLimit      = int32(20)
)

// activityRelatedResponse is the wire shape for GET /v1/activity/{id}/related.
type activityRelatedResponse struct {
	Event   ActivityEvent      `json:"event"`
	Related activityRelatedSet `json:"related"`
}

type activityRelatedSet struct {
	ByRequestID []ActivityEvent `json:"by_request_id"`
	ByActor     []ActivityEvent `json:"by_actor"`
}

// related serves GET /v1/activity/{id}/related: the anchor event, the events
// sharing its request_id, and the same actor's events within the time window.
// An unknown or other-tenant id is a 404; no event appears in both lists.
// event serves GET /tenants/{tenantID}/activity/{id}: one of the
// organisation's events, with its metadata, actor and browser. Another
// organisation's id answers 404, like an unknown one.
func (h *Handler) event(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.PathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid event id"))
		return
	}
	row, err := dbgen.New(h.pool).GetActivityEventByID(r.Context(), dbgen.GetActivityEventByIDParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, mapAuditRow(getRowToAuditRow(row)))
}

func (h *Handler) related(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid event id"))
		return
	}

	q := dbgen.New(h.pool)
	ctx := r.Context()

	anchorRow, err := q.GetActivityEventByID(ctx, dbgen.GetActivityEventByIDParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		ID:       id,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, r, errs.ErrNotFound)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	anchor := mapAuditRow(getRowToAuditRow(anchorRow))

	window := relatedDefaultWindow
	if raw := r.URL.Query().Get("window"); raw != "" {
		if secs, errW := strconv.ParseInt(raw, 10, 64); errW == nil && secs > 0 {
			window = time.Duration(secs) * time.Second
		}
	}
	if window < relatedMinWindow {
		window = relatedMinWindow
	}
	if window > relatedMaxWindow {
		window = relatedMaxWindow
	}

	seen := map[uuid.UUID]bool{id: true}

	byRequest := []ActivityEvent{}
	if anchorRow.RequestID != nil && *anchorRow.RequestID != "" {
		rows, errR := q.ListRelatedByRequestID(ctx, dbgen.ListRelatedByRequestIDParams{
			TenantID:  pgtype.UUID{Bytes: tenantID, Valid: true},
			RequestID: anchorRow.RequestID,
			ExcludeID: id,
			RowLimit:  relatedRowLimit,
		})
		if errR != nil {
			httpx.WriteError(w, r, errR)
			return
		}
		for _, row := range rows {
			ev := mapAuditRow(relatedRequestRowToAuditRow(row))
			seen[ev.ID] = true
			byRequest = append(byRequest, ev)
		}
	}

	byActor := []ActivityEvent{}
	if anchorRow.ActorUserID.Valid {
		rows, errA := q.ListRelatedByActor(ctx, dbgen.ListRelatedByActorParams{
			TenantID:  pgtype.UUID{Bytes: tenantID, Valid: true},
			ActorID:   anchorRow.ActorUserID,
			FromTs:    anchor.At.Add(-window),
			ToTs:      anchor.At.Add(window),
			ExcludeID: id,
			RowLimit:  relatedRowLimit,
		})
		if errA != nil {
			httpx.WriteError(w, r, errA)
			return
		}
		for _, row := range rows {
			ev := mapAuditRow(relatedActorRowToAuditRow(row))
			if seen[ev.ID] {
				continue // already surfaced under by_request_id
			}
			seen[ev.ID] = true
			byActor = append(byActor, ev)
		}
	}

	httpx.WriteJSON(w, http.StatusOK, activityRelatedResponse{
		Event: anchor,
		Related: activityRelatedSet{
			ByRequestID: byRequest,
			ByActor:     byActor,
		},
	})
}

// encodeCursor packs (createdAt, id) into an opaque base64url token whose text
// is "<RFC3339Nano>:<uuid>".
func encodeCursor(createdAt time.Time, id uuid.UUID) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor parses a cursor token, splitting its text at the last colon:
// the timestamp contains colons and the UUID none. It returns
// errs.ErrBadRequest for malformed input.
func decodeCursor(cursor string) (time.Time, uuid.UUID, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	idx := strings.LastIndex(string(b), ":")
	if idx < 0 {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	ts, err := time.Parse(time.RFC3339Nano, string(b[:idx]))
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	id, err := uuid.Parse(string(b[idx+1:]))
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	return ts, id, nil
}

// listRowToAuditRow converts a sqlc-generated ListActivityHistoryRow into the
// local auditRow type so that the shared mapAuditRow logic can be reused.
func listRowToAuditRow(r dbgen.ListActivityHistoryRow) auditRow {
	row := auditRow{
		ID:           r.ID,
		ActorType:    r.ActorType,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		ActorName:    firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:    r.CreatedAt,
		Metadata:     r.Metadata,
		TenantID:     uuid.UUID(r.TenantID.Bytes),
	}
	if r.ActorUserID.Valid {
		uid := uuid.UUID(r.ActorUserID.Bytes)
		row.ActorUserID = &uid
	}
	if r.ResourceID.Valid {
		rid := uuid.UUID(r.ResourceID.Bytes)
		row.ResourceID = &rid
	}
	if r.Ip != "" {
		row.IP = &r.Ip
	}
	return row
}

// replayRowToAuditRow converts a sqlc-generated ReplayActivityHistoryRow into
// the local auditRow type so that the shared mapAuditRow logic can be reused.
func replayRowToAuditRow(r dbgen.ReplayActivityHistoryRow) auditRow {
	row := auditRow{
		ID:           r.ID,
		ActorType:    r.ActorType,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		ActorName:    firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:    r.CreatedAt,
		Metadata:     r.Metadata,
		TenantID:     uuid.UUID(r.TenantID.Bytes),
	}
	if r.ActorUserID.Valid {
		uid := uuid.UUID(r.ActorUserID.Bytes)
		row.ActorUserID = &uid
	}
	if r.ResourceID.Valid {
		rid := uuid.UUID(r.ResourceID.Bytes)
		row.ResourceID = &rid
	}
	if r.Ip != "" {
		row.IP = &r.Ip
	}
	return row
}

// getRowToAuditRow converts a GetActivityEventByIDRow (the related-events anchor)
// into the local auditRow so mapAuditRow can be reused.
func getRowToAuditRow(r dbgen.GetActivityEventByIDRow) auditRow {
	row := auditRow{
		ID:           r.ID,
		ActorType:    r.ActorType,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		ActorName:    firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:    r.CreatedAt,
		Metadata:     r.Metadata,
		TenantID:     uuid.UUID(r.TenantID.Bytes),
	}
	if r.ActorUserID.Valid {
		uid := uuid.UUID(r.ActorUserID.Bytes)
		row.ActorUserID = &uid
	}
	if r.ResourceID.Valid {
		rid := uuid.UUID(r.ResourceID.Bytes)
		row.ResourceID = &rid
	}
	if r.Ip != "" {
		row.IP = &r.Ip
	}
	return row
}

// relatedRequestRowToAuditRow converts a ListRelatedByRequestIDRow into auditRow.
func relatedRequestRowToAuditRow(r dbgen.ListRelatedByRequestIDRow) auditRow {
	row := auditRow{
		ID:           r.ID,
		ActorType:    r.ActorType,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		ActorName:    firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:    r.CreatedAt,
		Metadata:     r.Metadata,
		TenantID:     uuid.UUID(r.TenantID.Bytes),
	}
	if r.ActorUserID.Valid {
		uid := uuid.UUID(r.ActorUserID.Bytes)
		row.ActorUserID = &uid
	}
	if r.ResourceID.Valid {
		rid := uuid.UUID(r.ResourceID.Bytes)
		row.ResourceID = &rid
	}
	if r.Ip != "" {
		row.IP = &r.Ip
	}
	return row
}

// relatedActorRowToAuditRow converts a ListRelatedByActorRow into auditRow.
func relatedActorRowToAuditRow(r dbgen.ListRelatedByActorRow) auditRow {
	row := auditRow{
		ID:           r.ID,
		ActorType:    r.ActorType,
		Action:       r.Action,
		ResourceType: r.ResourceType,
		UserAgent:    r.UserAgent,
		RequestID:    r.RequestID,
		ActorName:    firstNonEmpty(r.ActorDisplayName, r.ActorEmail),
		CreatedAt:    r.CreatedAt,
		Metadata:     r.Metadata,
		TenantID:     uuid.UUID(r.TenantID.Bytes),
	}
	if r.ActorUserID.Valid {
		uid := uuid.UUID(r.ActorUserID.Bytes)
		row.ActorUserID = &uid
	}
	if r.ResourceID.Valid {
		rid := uuid.UUID(r.ResourceID.Bytes)
		row.ResourceID = &rid
	}
	if r.Ip != "" {
		row.IP = &r.Ip
	}
	return row
}

// requireTenantUser returns the tenant and user of the authenticated principal.
// If either is missing it writes the error response and returns ok=false.
func (h *Handler) requireTenantUser(w http.ResponseWriter, r *http.Request) (tenantID uuid.UUID, userID uuid.UUID, ok bool) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = httpx.RequireUser(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return uuid.Nil, uuid.Nil, false
	}
	return tenantID, userID, true
}

// splitCSV splits a comma-separated query parameter into a []string, trimming
// whitespace around each element. Returns nil when s is empty.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sseWriter writes SSE frames to a ResponseWriter, flushing after each. Its
// mutex serialises the handler's events with the keep-alive goroutine's pings,
// which would otherwise interleave mid-frame. It copies the qeetai writer rather
// than importing that package.
type sseWriter struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher

	pingDone chan struct{} // closed by the keep-alive goroutine on exit
}

// newSSEWriter wraps w for SSE use. It returns nil if w is not an http.Flusher.
func newSSEWriter(w http.ResponseWriter) *sseWriter {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return &sseWriter{w: w, flusher: f}
}

// write emits one pre-formatted frame under the lock.
func (s *sseWriter) write(frame string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A failed write means the client has gone; the handler returns when the
	// request context is cancelled, so there is nothing to do here.
	_, _ = fmt.Fprint(s.w, frame) // #nosec G705 -- a text/event-stream of JSON frames and server-encoded cursors, never HTML
	s.flusher.Flush()
}

// sendActivity writes one "id: <cursor>\nevent: activity\ndata: <json>\n\n"
// SSE frame. The id is the cursor of the event at cursorAt, which a
// reconnecting client sends back as Last-Event-ID.
func (s *sseWriter) sendActivity(ev ActivityEvent, cursorAt time.Time) {
	raw, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("activity: sse marshal", "err", err)
		return
	}
	s.write(fmt.Sprintf("id: %s\nevent: activity\ndata: %s\n\n", encodeCursor(cursorAt, ev.ID), raw))
}

// sendCursor writes a frame holding only the cursor of the audit row at at,
// id: the client keeps it as its Last-Event-ID without an event to show.
func (s *sseWriter) sendCursor(at time.Time, id uuid.UUID) {
	s.write(fmt.Sprintf("id: %s\n\n", encodeCursor(at, id)))
}

// retryLater sets the client's reconnect delay to shutdownRetry, for a stream
// about to end so the client reconnects: the server is stopping, or the
// client must catch up from the audit log.
func (s *sseWriter) retryLater() {
	s.write(fmt.Sprintf("retry: %d\n\n", shutdownRetry.Milliseconds()))
}

// keepAlive sends an SSE comment frame so proxies do not close an idle
// connection.
func (s *sseWriter) keepAlive() {
	s.write(": keep-alive\n\n")
}

// startKeepAlive starts a goroutine that sends a keep-alive every d until stop
// is closed. Pair every call with stopKeepAlive.
func (s *sseWriter) startKeepAlive(stop <-chan struct{}, d time.Duration) {
	s.pingDone = make(chan struct{})
	go func() {
		defer close(s.pingDone)
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				s.keepAlive()
			}
		}
	}()
}

// stopKeepAlive blocks until the keep-alive goroutine has returned, so nothing
// writes to the ResponseWriter after the handler returns. Closing the stop
// channel alone does not wait for a ping already in progress.
func (s *sseWriter) stopKeepAlive() {
	if s.pingDone != nil {
		<-s.pingDone
	}
}
