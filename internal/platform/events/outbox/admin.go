package outbox

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
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

// Mount registers nothing.
//
// This package previously exposed the DLQ at GET /v1/admin/outbox/dlq, with a
// comment saying the caller was "expected to gate this behind a platform-admin
// permission check at the router level". No such gate existed, and none could:
// the route was mapped to the `audit.read` permission, which rbac.Enforce
// evaluates against *the caller's own tenant*. Every customer's org owner/admin
// holds it, so any of them could read every other tenant's dead-lettered event
// payloads — user records, group names, verified domains, credential subjects.
// platform.outbox_dead_letter has no tenant_id column, so the query could not
// be scoped either.
//
// The DLQ is now operator-only, inspected via direct database access. That is
// already how the live queue is handled (see the Reader doc comment) — this
// simply applies the same rule to the dead-letter table. Reader is retained for
// that use and for tests.
//
// Do not re-mount this on the tenant-scoped API without either a real
// platform-operator principal or a tenant_id column to filter on.
func (h *Handler) Mount(chi.Router) {}
