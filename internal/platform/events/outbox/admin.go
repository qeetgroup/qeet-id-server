package outbox

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reader reads the dead-letter table for operator triage.
type Reader struct {
	pool *pgxpool.Pool
}

// NewReader returns a Reader over pool.
func NewReader(pool *pgxpool.Pool) *Reader { return &Reader{pool: pool} }

// DLQRow is one dead-lettered event.
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

// ListDLQ returns up to limit dead-lettered events, newest first. A limit
// outside 1..200 becomes 50.
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

// Handler holds the dead-letter Reader; its Mount serves nothing.
type Handler struct {
	Reader *Reader
}

// Mount registers no routes. The dead-letter table has no tenant_id, so it
// can't be served on the tenant-scoped API; operators read it from the
// database. Mount it only with a platform-operator principal or a tenant column.
func (h *Handler) Mount(chi.Router) {}
