package outbox

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// failingPublisher fails its first failuresLeft publishes, then succeeds.
type failingPublisher struct {
	failuresLeft int
	publishes    []string
}

func (p *failingPublisher) Publish(_ context.Context, m Message) error {
	p.publishes = append(p.publishes, m.EventType)
	if p.failuresLeft > 0 {
		p.failuresLeft--
		return errors.New("simulated transient failure")
	}
	return nil
}

func TestLogPublisher_AlwaysSucceeds(t *testing.T) {
	if err := (LogPublisher{}).Publish(context.Background(), Message{ID: uuid.New(), Topic: "t", EventType: "e", Payload: []byte("{}")}); err != nil {
		t.Fatalf("LogPublisher must never fail, got %v", err)
	}
}

func TestDefaultMaxAttempts_IsReasonable(t *testing.T) {
	if DefaultMaxAttempts < 5 {
		t.Errorf("max attempts too low: %d — transient publisher outages need room to ride out", DefaultMaxAttempts)
	}
	if DefaultMaxAttempts > 30 {
		t.Errorf("max attempts too high: %d — log spam from permanently-bad events", DefaultMaxAttempts)
	}
}

func TestPublisherAdapter_RecordsEventTypes(t *testing.T) {
	p := &failingPublisher{failuresLeft: 2}
	ctx := context.Background()
	_ = p.Publish(ctx, Message{ID: uuid.New(), Topic: "topic", EventType: "type-1", Payload: []byte("{}")})
	_ = p.Publish(ctx, Message{ID: uuid.New(), Topic: "topic", EventType: "type-2", Payload: []byte("{}")})
	_ = p.Publish(ctx, Message{ID: uuid.New(), Topic: "topic", EventType: "type-3", Payload: []byte("{}")})
	if len(p.publishes) != 3 {
		t.Errorf("publishes recorded = %v, want 3", p.publishes)
	}
	if p.failuresLeft != 0 {
		t.Errorf("failures-left should be 0 after exhaustion, got %d", p.failuresLeft)
	}
}
