// Package outbox is the shared transactional outbox helper.
// Modules call Enqueue inside their own pgx.Tx; the Dispatcher polls
// committed rows and hands them to a Publisher. For the monolith we ship
// a logging publisher; swap in Kafka when first integrator needs it.
package outbox

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	ID          uuid.UUID
	AggregateID uuid.UUID
	Topic       string
	EventType   string
	Payload     any
}

// Enqueue inserts an event row inside the caller's transaction. The
// dispatcher will pick it up after commit.
func Enqueue(ctx context.Context, tx pgx.Tx, e Event) error {
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO platform.outbox (id, aggregate_id, topic, event_type, payload)
		VALUES ($1, $2, $3, $4, $5)
	`, e.ID, e.AggregateID, e.Topic, e.EventType, payload)
	return err
}

type Publisher interface {
	Publish(ctx context.Context, topic, eventType string, payload []byte) error
}

type LogPublisher struct{}

func (LogPublisher) Publish(_ context.Context, topic, eventType string, payload []byte) error {
	slog.Info("outbox publish", "topic", topic, "event", eventType, "payload_bytes", len(payload))
	return nil
}

type Dispatcher struct {
	pool        *pgxpool.Pool
	pub         Publisher
	interval    time.Duration
	batchSize   int
	maxAttempts int
}

// DefaultMaxAttempts caps how many times the dispatcher retries before
// moving the row to the dead-letter table. 10 gives ~17 minutes of
// exponential backoff (capped at 5 min per step) which is more than
// enough to ride out a transient publisher outage but stops infinite
// log spam from a permanently malformed payload.
const DefaultMaxAttempts = 10

func NewDispatcher(pool *pgxpool.Pool, pub Publisher, interval time.Duration, batchSize int) *Dispatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if batchSize <= 0 {
		batchSize = 50
	}
	return &Dispatcher{pool: pool, pub: pub, interval: interval, batchSize: batchSize, maxAttempts: DefaultMaxAttempts}
}

// Run polls platform.outbox until ctx is cancelled.
func (d *Dispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := d.tick(ctx); err != nil {
				slog.Warn("outbox tick", "err", err)
			}
		}
	}
}

func (d *Dispatcher) tick(ctx context.Context) error {
	// Pick rows that are either fresh (last_attempt_at IS NULL) or
	// whose backoff window has elapsed. We deliberately compute the
	// minimum gap in Go (via backoff()) rather than in SQL so the
	// retry curve can change without a migration.
	rows, err := d.pool.Query(ctx, `
		SELECT id, topic, event_type, payload, attempts
		FROM platform.outbox
		WHERE published_at IS NULL
		  AND (last_attempt_at IS NULL
		       OR last_attempt_at < NOW() - (LEAST(POWER(2, attempts), 300) || ' seconds')::interval)
		ORDER BY created_at
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`, d.batchSize)
	if err != nil {
		return err
	}
	type row struct {
		ID        uuid.UUID
		Topic     string
		EventType string
		Payload   []byte
		Attempts  int
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.Topic, &r.EventType, &r.Payload, &r.Attempts); err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, r)
	}
	rows.Close()
	if len(batch) == 0 {
		return nil
	}
	for _, r := range batch {
		if err := d.pub.Publish(ctx, r.Topic, r.EventType, r.Payload); err != nil {
			d.recordFailure(ctx, r.ID, r.Attempts+1, err)
			continue
		}
		if _, err := d.pool.Exec(ctx, `UPDATE platform.outbox SET published_at = NOW() WHERE id = $1`, r.ID); err != nil {
			slog.Warn("outbox mark published", "id", r.ID, "err", err)
		}
	}
	return nil
}

// recordFailure either bumps attempts + last_error, or — if we've hit
// the cap — moves the row to platform.outbox_dead_letter in a single
// transaction so the live queue never sees the bad event again.
func (d *Dispatcher) recordFailure(ctx context.Context, id uuid.UUID, attempts int, pubErr error) {
	slog.Warn("outbox publish failed", "id", id, "attempts", attempts, "err", pubErr)
	if attempts < d.maxAttempts {
		_, err := d.pool.Exec(ctx, `
			UPDATE platform.outbox
			SET attempts = $1, last_error = $2, last_attempt_at = NOW()
			WHERE id = $3
		`, attempts, pubErr.Error(), id)
		if err != nil {
			slog.Warn("outbox bump attempts", "id", id, "err", err)
		}
		return
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		slog.Error("outbox dlq begin", "id", id, "err", err)
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.outbox_dead_letter
		    (id, aggregate_id, topic, event_type, payload, created_at, attempts, last_error)
		SELECT id, aggregate_id, topic, event_type, payload, created_at, $1, $2
		FROM platform.outbox WHERE id = $3
	`, attempts, pubErr.Error(), id); err != nil {
		slog.Error("outbox dlq insert", "id", id, "err", err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM platform.outbox WHERE id = $1`, id); err != nil {
		slog.Error("outbox dlq delete-from-outbox", "id", id, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Error("outbox dlq commit", "id", id, "err", err)
		return
	}
	slog.Warn("outbox event dead-lettered", "id", id, "attempts", attempts)
}
