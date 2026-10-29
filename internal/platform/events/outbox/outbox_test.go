package outbox

import (
	"context"
	"errors"
	"testing"
	"time"

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

// TestRetriesSpanADay checks that an event is retried for at least
// DeadLetterAfter, and not much longer, before it is dead-lettered, waiting
// longer after each failure up to retryCap.
func TestRetriesSpanADay(t *testing.T) {
	var waited time.Duration
	for n := 1; n < DefaultMaxAttempts; n++ {
		if d := retryDelay(n); d < retryDelay(n-1) || d > retryCap {
			t.Fatalf("wait after failure %d is %s; want it no shorter than the last and at most %s", n, d, retryCap)
		}
		waited += retryDelay(n)
	}
	if waited < DeadLetterAfter || waited >= DeadLetterAfter+retryCap {
		t.Errorf("%d attempts span %s, want at least %s and under %s more", DefaultMaxAttempts, waited, DeadLetterAfter, retryCap)
	}
	if retryDelay(1) != 2*time.Second || retryDelay(1000) != retryCap {
		t.Errorf("waits %s after one failure and %s after many, want 2s and %s", retryDelay(1), retryDelay(1000), retryCap)
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
