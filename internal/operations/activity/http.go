package activity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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

// Handler is the HTTP surface for the Live Activity feature: a real-time SSE
// stream and a cursor-paginated history endpoint, both tenant-scoped.
type Handler struct {
	Hub  *Hub
	pool *pgxpool.Pool
}

// NewHandler constructs an activity Handler. pool is used for the history
// query (reads from audit.events). hub provides live NATS fan-out.
func NewHandler(pool *pgxpool.Pool, hub *Hub) *Handler {
	return &Handler{pool: pool, Hub: hub}
}

// Mount registers the activity endpoints on the authenticated router group.
// Both routes are gated by "audit.read" in the central permissionMap.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/activity", h.history)
	r.Get("/activity/summary", h.summary)
	r.Get("/activity/stream", h.stream)
	r.Get("/activity/{id}/related", h.related)
}

// stream handles GET /v1/activity/stream.
//
// On connect the handler optionally replays recent audit events the client
// missed (when Last-Event-ID is present), then fans out live events from the
// hub until the client disconnects. Server-side filters are applied to both the
// replay and the live stream.
//
// The write deadline is extended to 1 hour (HTTP_WRITE_TIMEOUT default of 30s
// is far too short for a long-lived SSE stream). X-Accel-Buffering is disabled
// so Nginx/Caddy do not buffer SSE frames.
func (h *Handler) stream(w http.ResponseWriter, r *http.Request) {
	tenantID, _, ok := h.requireTenantUser(w, r)
	if !ok {
		return
	}

	f := StreamFilter{
		Types:    splitCSV(r.URL.Query().Get("types")),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
	}

	// Extend the write deadline so the long-lived SSE connection is not
	// truncated by the server's HTTP_WRITE_TIMEOUT (default 30s). Reset to
	// 1 hour from now; the ticker keep-alive will prevent idle closures.
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
	donePing := make(chan struct{})
	defer close(donePing)
	sse.startKeepAlive(donePing, 20*time.Second)

	ctx := r.Context()

	// Replay events the client missed since Last-Event-ID. This covers the
	// reconnect case: the client sends the ID of the last event it received and
	// we replay everything newer from the audit log before switching to live.
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		h.replayHistory(ctx, sse, tenantID, lastID, f)
	}

	evCh, unsub := h.Hub.Subscribe(tenantID)
	defer unsub()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-evCh:
			// Defense-in-depth: verify the event's own TenantID matches the
			// authenticated connection's tenant. The hub already routes by tenant;
			// this guard catches any hub mis-routing before it becomes a
			// cross-tenant SSE leak. Unlike the previous check (which compared
			// two values derived from the same JWT principal and was a tautology),
			// this inspects the actual event payload's TenantID field.
			if ev.TenantID != tenantID {
				slog.Error("activity: cross-tenant event dropped at write boundary",
					"connection_tenant", tenantID,
					"event_tenant", ev.TenantID)
				continue
			}
			if !matchesStreamFilter(ev, f) {
				continue
			}
			sse.sendActivity(ev)
		}
	}
}

// replayHistory fetches audit events newer than the cursor encoded in
// lastEventID and streams them to the client in chronological order (oldest
// first), mirroring the order a continuously-connected client would have seen.
//
// lastEventID is a base64url-encoded cursor of the form
// "<RFC3339Nano created_at>:<uuid>". Anything that fails to decode is silently
// skipped so a reconnect with an invalid / stale ID just starts live.
func (h *Handler) replayHistory(ctx context.Context, sse *sseWriter, tenantID uuid.UUID, lastEventID string, f StreamFilter) {
	afterTs, afterID, err := decodeCursor(lastEventID)
	if err != nil {
		return // invalid Last-Event-ID — skip replay rather than erroring
	}

	rows, err := dbgen.New(h.pool).ReplayActivityHistory(ctx, dbgen.ReplayActivityHistoryParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		AfterTs:  afterTs,
		AfterID:  afterID,
	})
	if err != nil {
		slog.Warn("activity: replay query", "err", err)
		return
	}

	for _, row := range rows {
		ev := mapAuditRow(replayRowToAuditRow(row))
		if !matchesStreamFilter(ev, f) {
			continue
		}
		sse.sendActivity(ev)
	}
}

// history handles GET /v1/activity.
//
// Returns a cursor-paginated list of ActivityEvent mapped from the audit log.
// Tenant is derived from the JWT principal only (never from the URL or body).
func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cursor := r.URL.Query().Get("cursor")
	f := parseListFilter(r)

	events, next, err := h.listHistory(r.Context(), tenantID, f, cursor, limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if events == nil {
		events = []ActivityEvent{}
	}

	resp := map[string]any{"events": events}
	if next != "" {
		resp["next_cursor"] = next
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// listHistory executes the static audit-events query and returns ActivityEvents.
//
// The cursor is an opaque base64url token encoding (created_at, id) of the
// last event on the previous page. Severity and Category are post-fetch filters
// because they are derived values not stored in audit.events.
func (h *Handler) listHistory(ctx context.Context, tenantID uuid.UUID, f ListFilter, cursor string, limit int) ([]ActivityEvent, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	// Fetch a larger page when post-fetch filters are active.
	fetchLimit := limit + 1
	if f.Severity != "" || f.Category != "" {
		fetchLimit = min(limit*3+1, 201)
	}

	// Build the typed params for the sqlc query. Null-able nargs are expressed
	// via pgtype wrappers: a zero-value (Valid=false) passes NULL to the DB,
	// which the IS NULL predicate treats as "no filter on this dimension."
	params := dbgen.ListActivityHistoryParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Actions:  f.Types, // nil slice → NULL → no filter
		RowLimit: int32(fetchLimit),
	}

	if f.ActorID != uuid.Nil {
		params.ActorID = pgtype.UUID{Bytes: f.ActorID, Valid: true}
	}
	if f.Subject != nil {
		params.Subject = pgtype.UUID{Bytes: *f.Subject, Valid: true}
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

	out := []ActivityEvent{}
	for _, row := range dbRows {
		ev := mapAuditRow(listRowToAuditRow(row))
		if !matchesListFilter(ev, f) {
			continue
		}
		out = append(out, ev)
		// Stop scanning once we have limit+1 matching rows — enough to know
		// whether a next page exists without over-allocating.
		if len(out) == limit+1 {
			break
		}
	}

	var next string
	if len(out) > limit {
		last := out[limit]
		next = encodeCursor(last.At, last.ID)
		out = out[:limit]
	}
	return out, next, nil
}

// parseListFilter builds a ListFilter from the request's query params. It is
// shared by history and summary so both honour identical predicates
// (types, severity, category, actor, subject, q, from, to). limit and cursor are
// history-only and parsed by the caller.
func parseListFilter(r *http.Request) ListFilter {
	f := ListFilter{
		Types:    splitCSV(r.URL.Query().Get("types")),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("q"),
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
	return f
}

// Summary window bounds. Without an explicit `from`, the summary defaults to the
// last 24h; the window is hard-capped at 90d so a per-tenant aggregate (notably
// count(DISTINCT actor_user_id)) can never scan unbounded history.
const (
	summaryDefaultWindow = 24 * time.Hour
	summaryMaxWindow     = 90 * 24 * time.Hour
	summaryDefaultBucket = int64(3600) // 1h buckets
	summaryMinBucket     = int64(60)
	summaryMaxBucket     = int64(86400)
	summaryTargetBuckets = 48
)

// activitySummaryResponse is the aggregate wire shape for GET /v1/activity/summary.
type activitySummaryResponse struct {
	Total          int64            `json:"total"`
	UniqueActors   int64            `json:"unique_actors"`
	SecurityAlerts int64            `json:"security_alerts"`
	BySeverity     map[string]int64 `json:"by_severity"`
	ByCategory     map[string]int64 `json:"by_category"`
	ByOutcome      map[string]int64 `json:"by_outcome"`
	Series         []summaryBucket  `json:"series"`
	BucketSeconds  int64            `json:"bucket_seconds"`
	Window         summaryWindow    `json:"window"`
}

// summaryBucket is one time slice of the sparkline series. Total is all events
// in the bucket; the remaining fields are per-outcome/severity breakdowns so the
// console can draw a distinct sparkline per metric card.
type summaryBucket struct {
	At       time.Time `json:"at"`
	Count    int64     `json:"count"` // total (kept as `count` for back-compat)
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

// summary handles GET /v1/activity/summary.
//
// It returns aggregate counts over the SAME filter predicates as history
// (types, actor, subject, from/to, q) but deliberately IGNORES the severity and
// category filters — its job is to PRODUCE the severity/category/outcome
// distribution, so filtering by them would be self-contradictory. Severity,
// category and outcome are derived from the action string (not columns), so the
// per-action GROUP BY is folded into buckets in Go via severityOf/categoryOf/
// outcomeOf — the single source of truth for that derivation.
func (h *Handler) summary(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	f := parseListFilter(r)

	// Resolve and bound the aggregation window. A missing lower bound defaults to
	// now-24h; the span is clamped to summaryMaxWindow.
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

	byAction, err := q.SummarizeActivityByAction(ctx, dbgen.SummarizeActivityByActionParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Actions:  f.Types,
		ActorID:  nargUUID(f.ActorID),
		Subject:  nargSubject(f.Subject),
		FromTs:   pgtype.Timestamptz{Time: from, Valid: true},
		ToTs:     pgtype.Timestamptz{Time: to, Valid: true},
		Q:        nargSearch(f.Search),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	totals, err := q.SummarizeActivityTotals(ctx, dbgen.SummarizeActivityTotalsParams{
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
		Actions:  f.Types,
		ActorID:  nargUUID(f.ActorID),
		Subject:  nargSubject(f.Subject),
		FromTs:   pgtype.Timestamptz{Time: from, Valid: true},
		ToTs:     pgtype.Timestamptz{Time: to, Valid: true},
		Q:        nargSearch(f.Search),
	})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	series, err := q.SummarizeActivityTimeSeries(ctx, dbgen.SummarizeActivityTimeSeriesParams{
		BucketSeconds: bucket,
		TenantID:      pgtype.UUID{Bytes: tenantID, Valid: true},
		Actions:       f.Types,
		ActorID:       nargUUID(f.ActorID),
		Subject:       nargSubject(f.Subject),
		FromTs:        pgtype.Timestamptz{Time: from, Valid: true},
		ToTs:          pgtype.Timestamptz{Time: to, Valid: true},
		Q:             nargSearch(f.Search),
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
	// ordered by bucket ASC so same-bucket rows are contiguous; we mutate the
	// tail bucket by index (no pointer aliasing across appends).
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
		Total:          totals.Total,
		UniqueActors:   totals.UniqueActors,
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

// related handles GET /v1/activity/{id}/related.
//
// It resolves the anchor event (tenant-scoped — an unknown id or a foreign
// tenant's id both surface as 404, never a cross-tenant leak), then returns
// events correlated by the anchor's request_id and by the same actor within a
// symmetric time window. An event never appears in both lists.
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

// nargUUID maps a possibly-Nil actor id to a nullable pgtype.UUID (Nil → NULL).
func nargUUID(id uuid.UUID) pgtype.UUID {
	if id == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: id, Valid: true}
}

// nargSubject maps a possibly-nil subject id to a nullable pgtype.UUID.
func nargSubject(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// nargSearch maps an empty search string to a nil *string (NULL predicate).
func nargSearch(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// encodeCursor packs (createdAt, id) into an opaque base64url token. The
// format is "<RFC3339Nano>:<uuid>" — sufficient precision for a timestamptz
// cursor and unambiguous when split on the first colon.
func encodeCursor(createdAt time.Time, id uuid.UUID) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + ":" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeCursor is the inverse of encodeCursor. Returns a non-nil error for
// any malformed input; callers pass the error straight to the handler.
func decodeCursor(cursor string) (time.Time, uuid.UUID, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
	}
	// Split on the first colon only — RFC3339Nano timestamps contain no colons
	// beyond the time-separator, but we split on index rather than strings.Cut
	// to stay robust if a future UUID format ever includes colons.
	idx := strings.Index(string(b), ":")
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

// requireTenantUser extracts and validates the tenant and user from the JWT
// principal. Handlers MUST use this; they must NEVER accept tenant/user from
// the URL or request body (QID-18 multi-tenancy invariant).
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

// sseWriter writes SSE frames to an http.ResponseWriter and flushes after each.
// It mirrors qeetai/sse.go — not imported because qeetai is not a shared
// library; copying the ~30-line writer keeps the package dependency graph clean.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// newSSEWriter wraps w for SSE use. Returns nil when w does not implement
// http.Flusher (should never happen with a real net/http response).
func newSSEWriter(w http.ResponseWriter) *sseWriter {
	f, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return &sseWriter{w: w, flusher: f}
}

// sendActivity writes one "event: activity\ndata: <json>\n\n" SSE frame.
func (s *sseWriter) sendActivity(ev ActivityEvent) {
	raw, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("activity: sse marshal", "err", err)
		return
	}
	fmt.Fprintf(s.w, "event: activity\ndata: %s\n\n", raw)
	s.flusher.Flush()
}

// keepAlive sends a comment ping (":\n\n") to prevent proxy timeouts on idle
// connections — identical to the qeetai keep-alive pattern.
func (s *sseWriter) keepAlive() {
	fmt.Fprintf(s.w, ": keep-alive\n\n")
	s.flusher.Flush()
}

// startKeepAlive launches a goroutine that sends keep-alive pings every d
// until done is closed.
func (s *sseWriter) startKeepAlive(done <-chan struct{}, d time.Duration) {
	go func() {
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.keepAlive()
			}
		}
	}()
}
