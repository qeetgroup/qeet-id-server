package activity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	r.Get("/activity/stream", h.stream)
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

	f := ListFilter{
		Types:    splitCSV(r.URL.Query().Get("types")),
		Severity: r.URL.Query().Get("severity"),
		Category: r.URL.Query().Get("category"),
		Search:   r.URL.Query().Get("q"),
	}

	if raw := r.URL.Query().Get("actor"); raw != "" {
		if id, err2 := uuid.Parse(raw); err2 == nil {
			f.ActorID = id
		}
	}
	if raw := r.URL.Query().Get("subject"); raw != "" {
		if id, err2 := uuid.Parse(raw); err2 == nil {
			f.Subject = &id
		}
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		if t, err2 := time.Parse(time.RFC3339, raw); err2 == nil {
			f.From = &t
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		if t, err2 := time.Parse(time.RFC3339, raw); err2 == nil {
			f.To = &t
		}
	}

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
// It mirrors copilot/sse.go — not imported because copilot is not a shared
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
// connections — identical to the copilot keep-alive pattern.
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
