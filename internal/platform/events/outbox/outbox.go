// Package outbox is the transactional outbox. Modules call Enqueue inside their
// own pgx.Tx; a Dispatcher polls committed rows and hands them to a Publisher
// (NATS, or a log-only default), retrying with backoff and dead-lettering rows
// that keep failing.
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

// Event is one message to publish once the enqueuing transaction commits.
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

// PublishedRetention is how long a published event is kept, to look into a
// delivery. Its payload can hold personal data, so it doesn't stay for good.
const PublishedRetention = 7 * 24 * time.Hour

// purgeBatch bounds each purge statement, so a long backlog is deleted in
// short statements rather than one that outlasts the statement timeout.
var purgeBatch = 5000

// PurgePublished deletes events published more than retention ago and returns
// how many. Unpublished and dead-lettered events are left alone.
func PurgePublished(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-retention)
	var total int64
	for {
		tag, err := pool.Exec(ctx, `
			DELETE FROM platform.outbox
			WHERE id IN (SELECT id FROM platform.outbox WHERE published_at < $1 LIMIT $2)
		`, cutoff, purgeBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(purgeBatch) {
			return total, nil
		}
	}
}

// Publisher delivers an event. A nil error marks the row published; an error
// makes the Dispatcher retry it.
type Publisher interface {
	Publish(ctx context.Context, eventID uuid.UUID, topic, eventType string, payload []byte) error
}

// LogPublisher logs each event instead of delivering it. It never fails.
type LogPublisher struct{}

func (LogPublisher) Publish(_ context.Context, eventID uuid.UUID, topic, eventType string, payload []byte) error {
	slog.Info("outbox publish", "event_id", eventID, "topic", topic, "event", eventType, "payload_bytes", len(payload))
	return nil
}

// Dispatcher leases due outbox rows in batches and publishes them. Leases make
// concurrent dispatchers safe.
type Dispatcher struct {
	pool        *pgxpool.Pool
	pub         Publisher
	interval    time.Duration
	batchSize   int
	maxAttempts int
	workerID    uuid.UUID
	lease       time.Duration
}

// DefaultMaxAttempts is how many publishes are tried before a row moves to the
// dead-letter table: about 14 minutes of backoff, enough to ride out a
// publisher outage without retrying a malformed payload forever.
const DefaultMaxAttempts = 10

// NewDispatcher returns a Dispatcher polling every interval (default 2s) in
// batches of batchSize (default 50).
func NewDispatcher(pool *pgxpool.Pool, pub Publisher, interval time.Duration, batchSize int) *Dispatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if batchSize <= 0 {
		batchSize = 50
	}
	return &Dispatcher{
		pool: pool, pub: pub, interval: interval, batchSize: batchSize,
		maxAttempts: DefaultMaxAttempts, workerID: uuid.New(), lease: 2 * time.Minute,
	}
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
	// Lease unleased rows that are new or whose backoff (2^attempts seconds,
	// capped at 300) has elapsed.
	rows, err := d.pool.Query(ctx, `
		WITH candidates AS (
			SELECT id
			FROM platform.outbox
			WHERE published_at IS NULL
			  AND (lease_until IS NULL OR lease_until <= NOW())
			  AND (last_attempt_at IS NULL
			       OR last_attempt_at < NOW() - (LEAST(POWER(2, attempts), 300) || ' seconds')::interval)
			ORDER BY created_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE platform.outbox AS event
		SET lease_owner = $2, lease_until = $3
		FROM candidates
		WHERE event.id = candidates.id
		RETURNING event.id, event.topic, event.event_type, event.payload, event.attempts
	`, d.batchSize, d.workerID, time.Now().UTC().Add(d.lease))
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
	err = rows.Err()
	rows.Close()
	// The query is an UPDATE ... RETURNING, so every row it produced is already
	// leased. Dropping unread rows silently strands those events until the lease
	// expires; surface it so the tick is retried instead.
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	for _, r := range batch {
		if err := d.pub.Publish(ctx, r.ID, r.Topic, r.EventType, r.Payload); err != nil {
			d.recordFailure(ctx, r.ID, r.Attempts+1, err)
			continue
		}
		if _, err := d.pool.Exec(ctx, `
			UPDATE platform.outbox
			SET published_at = NOW(), lease_owner = NULL, lease_until = NULL
			WHERE id = $1 AND lease_owner = $2
		`, r.ID, d.workerID); err != nil {
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
			SET attempts = $1, last_error = $2, last_attempt_at = NOW(),
			    lease_owner = NULL, lease_until = NULL
			WHERE id = $3 AND lease_owner = $4
		`, attempts, pubErr.Error(), id, d.workerID)
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
		FROM platform.outbox WHERE id = $3 AND lease_owner = $4
	`, attempts, pubErr.Error(), id, d.workerID); err != nil {
		slog.Error("outbox dlq insert", "id", id, "err", err)
		return
	}
	if _, err := tx.Exec(ctx, `DELETE FROM platform.outbox WHERE id = $1 AND lease_owner = $2`, id, d.workerID); err != nil {
		slog.Error("outbox dlq delete-from-outbox", "id", id, "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		slog.Error("outbox dlq commit", "id", id, "err", err)
		return
	}
	slog.Warn("outbox event dead-lettered", "id", id, "attempts", attempts)
}
