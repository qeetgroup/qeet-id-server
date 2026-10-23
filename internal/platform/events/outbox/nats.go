package outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// NATSPublisher publishes outbox events to NATS core: the topic is the subject,
// the payload the raw JSON, and the event ID and type ride in headers. Publish
// flushes before returning, so a broken connection is an error the dispatcher
// retries; at-least-once delivery comes from the outbox, not NATS.
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
func (p *NATSPublisher) Publish(ctx context.Context, m Message) error {
	msg := &nats.Msg{
		Subject: m.Topic,
		Data:    m.Payload,
		Header: nats.Header{
			"Qeet-Event-ID":   []string{m.ID.String()},
			"Qeet-Event-Type": []string{m.EventType},
		},
	}
	if err := p.nc.PublishMsg(msg); err != nil {
		return fmt.Errorf("nats publish %q: %w", m.Topic, err)
	}
	timeout := p.flushTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	if err := p.nc.FlushTimeout(timeout); err != nil {
		return fmt.Errorf("nats flush %q: %w", m.Topic, err)
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

// NewPublisher returns a NATSPublisher when natsURL is set, else LogPublisher,
// with a close func for the caller to defer (a no-op for LogPublisher).
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
