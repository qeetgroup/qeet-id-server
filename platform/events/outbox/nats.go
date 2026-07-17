package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// NATSPublisher publishes drained outbox events to NATS core. The event Topic is
// the NATS subject (topics are already dot-namespaced, e.g. "user.events"), the
// payload is the raw event JSON, and the event type rides in a header so
// subscribers can filter without decoding the body.
//
// At-least-once durability is owned by the outbox, not NATS core: a row is only
// marked published once Publish returns nil, so Publish flushes synchronously —
// a broken connection surfaces as an error and the dispatcher retries with
// backoff (and eventually dead-letters). This keeps the delivery contract
// identical to the LogPublisher path while adding a real broker.
type NATSPublisher struct {
	nc           *nats.Conn
	flushTimeout time.Duration
}

// NewNATSPublisher dials the NATS server at url (e.g. "nats://localhost:4222").
func NewNATSPublisher(url string) (*NATSPublisher, error) {
	nc, err := nats.Connect(url,
		nats.Name("qeet-id-outbox"),
		nats.MaxReconnects(-1), // reconnect forever; the dispatcher retries meanwhile
		nats.ReconnectWait(2*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("connect nats %q: %w", url, err)
	}
	return &NATSPublisher{nc: nc, flushTimeout: 5 * time.Second}, nil
}

// Publish sends one event to its topic subject and flushes, so a delivery
// failure is returned to the dispatcher (which retries) rather than silently
// buffered on a dead connection.
func (p *NATSPublisher) Publish(ctx context.Context, topic, eventType string, payload []byte) error {
	msg := &nats.Msg{
		Subject: topic,
		Data:    payload,
		Header:  nats.Header{"Qeet-Event-Type": []string{eventType}},
	}
	if err := p.nc.PublishMsg(msg); err != nil {
		return fmt.Errorf("nats publish %q: %w", topic, err)
	}
	timeout := p.flushTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	if err := p.nc.FlushTimeout(timeout); err != nil {
		return fmt.Errorf("nats flush %q: %w", topic, err)
	}
	return nil
}

// Close drains in-flight messages and closes the connection.
func (p *NATSPublisher) Close() error {
	if p.nc != nil {
		return p.nc.Drain()
	}
	return nil
}

// NewPublisher returns a NATS-backed publisher when natsURL is non-empty, and
// otherwise the dependency-free log-only publisher (the default). The returned
// close func should be deferred by the caller; it is a no-op for LogPublisher.
// This keeps both entrypoints (cmd/server, cmd/worker) on one code path.
func NewPublisher(natsURL string) (Publisher, func() error, error) {
	if natsURL == "" {
		return LogPublisher{}, func() error { return nil }, nil
	}
	np, err := NewNATSPublisher(natsURL)
	if err != nil {
		return nil, nil, err
	}
	return np, np.Close, nil
}
