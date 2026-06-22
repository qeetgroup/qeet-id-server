package outbox

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/httpx"
)

// Reader exposes the dead-letter table for ops triage. The live queue
// is intentionally not exposed — operators inspect it via direct DB
// access on the rare occasion they need to.
type Reader struct {
	pool *pgxpool.Pool
}

func NewReader(pool *pgxpool.Pool) *Reader { return &Reader{pool: pool} }

type DLQRow struct {
	ID             uuid.UUID       `json:"id"`
	AggregateID    uuid.UUID       `json:"aggregate_id"`
	Topic          string          `json:"topic"`
	EventType      string          `json:"event_type"`
	Payload        json.RawMessage `json:"payload"`
	CreatedAt      time.Time       `json:"created_at"`
	Attempts       int             `json:"attempts"`
	LastError      string          `json:"last_error"`
	DeadLetteredAt time.Time       `json:"dead_lettered_at"`
}

// ListDLQ returns the most recent dead-lettered events, newest first.
// Limit is clamped to 200 — heavier triage should query the DB
// directly. No cursor: by the time DLQ has more than 200 rows you
// have a much bigger ops problem than pagination.
func (r *Reader) ListDLQ(ctx context.Context, limit int) ([]DLQRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, aggregate_id, topic, event_type, payload,
		       created_at, attempts, COALESCE(last_error, ''), dead_lettered_at
		FROM platform.outbox_dead_letter
		ORDER BY dead_lettered_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DLQRow{}
	for rows.Next() {
		var d DLQRow
		if err := rows.Scan(&d.ID, &d.AggregateID, &d.Topic, &d.EventType, &d.Payload,
			&d.CreatedAt, &d.Attempts, &d.LastError, &d.DeadLetteredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type Handler struct {
	Reader *Reader
}

// Mount installs the DLQ inspector at /v1/admin/outbox/dlq. Caller is
// expected to gate this behind a platform-admin permission check at
// the router level — the handler itself does no auth.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/admin/outbox/dlq", h.list)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.Reader.ListDLQ(r.Context(), limit)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}
