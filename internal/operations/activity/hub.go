package activity

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// subBufSize is the capacity of each subscriber's channel. When it is full the
// hub drops the event rather than block the NATS goroutine, and tells the
// subscriber it has lost one.
const subBufSize = 256

// subscriber is the receive end of one SSE connection. lost is closed once an
// event couldn't be delivered to it.
type subscriber struct {
	tenantID uuid.UUID
	ch       chan ActivityEvent
	lost     chan struct{}
	lostOnce sync.Once
}

// Hub fans out domain events from the NATS outbox to the SSE subscribers of
// each event's tenant. An event for tenant X reaches only subscribers registered
// under X, and the stream handler checks the tenant again before writing. It is
// safe for concurrent use.
type Hub struct {
	mu   sync.RWMutex                // guards subs
	subs map[uuid.UUID][]*subscriber // tenantID → active subscribers

	stopping chan struct{} // closed by Shutdown
	stopOnce sync.Once
}

// NewHub returns a Hub subscribed to every NATS subject (">"). With a nil nc it
// delivers no live events, but streams still get keep-alives and history
// replay.
func NewHub(nc *nats.Conn) *Hub {
	h := &Hub{
		subs:     make(map[uuid.UUID][]*subscriber),
		stopping: make(chan struct{}),
	}
	if nc != nil {
		// Outbox topics are dot-namespaced ("user.events", "auth", …).
		if _, err := nc.Subscribe(">", h.dispatch); err != nil {
			slog.Error("activity hub: NATS subscribe failed", "err", err)
		} else {
			slog.Info("activity hub: subscribed to NATS outbox (all subjects)")
		}
	} else {
		slog.Info("activity hub: NATS not configured — live stream disabled (history+replay still works)")
	}
	return h
}

// Shutdown ends every open stream, and any opened later at once, each with a
// reconnect hint, so a stopping server's streams don't hold up its drain. It
// is safe to call more than once.
func (h *Hub) Shutdown() { h.stopOnce.Do(func() { close(h.stopping) }) }

// Subscribe registers a subscriber for tenantID and returns its event channel
// and an unsubscribe func the caller must call when the connection closes.
// tenantID must come from the authenticated principal.
func (h *Hub) Subscribe(tenantID uuid.UUID) (<-chan ActivityEvent, func()) {
	ch, _, unsub := h.subscribe(tenantID)
	return ch, unsub
}

// subscribe is Subscribe, also returning a channel closed once the subscriber
// has lost an event because it fell behind.
func (h *Hub) subscribe(tenantID uuid.UUID) (<-chan ActivityEvent, <-chan struct{}, func()) {
	s := &subscriber{
		tenantID: tenantID,
		ch:       make(chan ActivityEvent, subBufSize),
		lost:     make(chan struct{}),
	}

	h.mu.Lock()
	h.subs[tenantID] = append(h.subs[tenantID], s)
	h.mu.Unlock()

	return s.ch, s.lost, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		list := h.subs[tenantID]
		for i, sub := range list {
			if sub == s {
				// O(n), but a tenant rarely has more than a few connections.
				h.subs[tenantID] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(h.subs[tenantID]) == 0 {
			delete(h.subs, tenantID)
		}
	}
}

// dispatch is the NATS message handler. It runs on the NATS goroutine, so it
// only maps the message to an ActivityEvent and fans it out.
func (h *Hub) dispatch(msg *nats.Msg) {
	// The publisher sets the event type in the Qeet-Event-Type header; skip
	// messages without it.
	eventType := msg.Header.Get("Qeet-Event-Type")
	if eventType == "" {
		return
	}

	// Events without a tenant_id, such as platform system events, have no
	// subscribers.
	var tip struct {
		TenantID *uuid.UUID `json:"tenant_id"`
	}
	if err := json.Unmarshal(msg.Data, &tip); err != nil || tip.TenantID == nil {
		return
	}
	tenantID := *tip.TenantID

	ev := mapOutboxEvent(msg.Subject, eventType, tenantID, msg.Data)
	h.fanOut(tenantID, ev)
}

// fanOut delivers ev to every subscriber of tenantID without blocking. A
// subscriber whose channel is full doesn't get it and is told it lost an
// event, so its stream can have the client catch up from the audit log. It
// holds the read lock throughout, because unsubscribe rewrites the slice it
// iterates.
func (h *Hub) fanOut(tenantID uuid.UUID, ev ActivityEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, s := range h.subs[tenantID] {
		select {
		case s.ch <- ev:
		default:
			s.lostOnce.Do(func() {
				close(s.lost)
				slog.Warn("activity hub: subscriber fell behind; its stream reconnects",
					"tenant_id", tenantID, "event_type", ev.Type)
			})
		}
	}
}
