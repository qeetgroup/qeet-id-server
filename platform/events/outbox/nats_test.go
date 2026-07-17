package outbox

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// natsURL returns the broker URL for the NATS tests, or "" to signal skip.
// Defaults to the conventional local port; override with NATS_TEST_URL.
func natsURL() string {
	if u := os.Getenv("NATS_TEST_URL"); u != "" {
		return u
	}
	return "nats://127.0.0.1:4222"
}

// TestNATSPublisher_PublishesToSubject verifies the publisher delivers the event
// to a subscriber on the topic subject, carrying the raw payload and the event
// type header. Skips when no broker is reachable so the default `go test ./...`
// stays broker-free.
func TestNATSPublisher_PublishesToSubject(t *testing.T) {
	url := natsURL()
	sub, err := nats.Connect(url, nats.Timeout(2*time.Second))
	if err != nil {
		t.Skipf("no NATS broker at %s: %v", url, err)
	}
	defer sub.Close()

	const subject = "test.events"
	got := make(chan *nats.Msg, 1)
	s, err := sub.Subscribe(subject, func(m *nats.Msg) { got <- m })
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer func() { _ = s.Unsubscribe() }()
	if err := sub.Flush(); err != nil {
		t.Fatalf("flush subscription: %v", err)
	}

	pub, err := NewNATSPublisher(url)
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer func() { _ = pub.Close() }()

	payload := []byte(`{"hello":"world"}`)
	if err := pub.Publish(context.Background(), subject, "test.created", payload); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case m := <-got:
		if string(m.Data) != string(payload) {
			t.Fatalf("payload = %q, want %q", m.Data, payload)
		}
		if h := m.Header.Get("Qeet-Event-Type"); h != "test.created" {
			t.Fatalf("event-type header = %q, want test.created", h)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not receive the published message within 3s")
	}
}

// TestNewPublisher_DefaultsToLog verifies the dependency-free default: an empty
// URL yields the log-only publisher and a no-op close. Runs without a broker.
func TestNewPublisher_DefaultsToLog(t *testing.T) {
	p, closeFn, err := NewPublisher("")
	if err != nil {
		t.Fatalf("NewPublisher(\"\"): %v", err)
	}
	defer func() { _ = closeFn() }()
	if _, ok := p.(LogPublisher); !ok {
		t.Fatalf("empty NATS URL should yield LogPublisher, got %T", p)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("LogPublisher close should be a no-op, got %v", err)
	}
}
