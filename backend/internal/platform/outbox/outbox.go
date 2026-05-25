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
	pool      *pgxpool.Pool
	pub       Publisher
	interval  time.Duration
	batchSize int
}

func NewDispatcher(pool *pgxpool.Pool, pub Publisher, interval time.Duration, batchSize int) *Dispatcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if batchSize <= 0 {
		batchSize = 50
	}
	return &Dispatcher{pool: pool, pub: pub, interval: interval, batchSize: batchSize}
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
	rows, err := d.pool.Query(ctx, `
		SELECT id, topic, event_type, payload
		FROM platform.outbox
		WHERE published_at IS NULL
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
	}
	var batch []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.Topic, &r.EventType, &r.Payload); err != nil {
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
			slog.Warn("outbox publish failed", "id", r.ID, "err", err)
			continue
		}
		_, err := d.pool.Exec(ctx, `UPDATE platform.outbox SET published_at = NOW() WHERE id = $1`, r.ID)
		if err != nil {
			slog.Warn("outbox mark published", "id", r.ID, "err", err)
		}
	}
	return nil
}
