package activity

import (
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// subBufSize is the per-subscriber channel capacity. 256 events provides a
// comfortable burst buffer for a slow SSE consumer without wasting much memory.
// When full, the hub drops the oldest event (never blocks the NATS goroutine).
const subBufSize = 256

// subscriber is one SSE connection's receive end. Each connection gets its own
// buffered channel routed exclusively to its tenant.
type subscriber struct {
	tenantID uuid.UUID
	ch       chan ActivityEvent
}

// Hub is an in-process fan-out broker that receives domain events from the NATS
// outbox and delivers them to the SSE connections that belong to the same tenant.
//
// Security invariant: an event published to tenantID X is delivered ONLY to
// subscribers registered under tenantID X. The routing key (payload.tenant_id)
// is extracted from the message body and independently checked by the SSE
// handler against the JWT principal's tenant — belt-and-suspenders isolation.
//
// When nc is nil (NATS_URL not configured) the hub acts as a no-op broker:
// SSE connections still connect and receive keep-alives + history replays,
// but no live events are delivered.
type Hub struct {
	mu   sync.RWMutex
	subs map[uuid.UUID][]*subscriber // tenantID → active subscribers
}

// NewHub constructs and starts the Hub. If nc is non-nil the hub subscribes to
// the NATS wildcard subject ">" (matches all outbox topics) and routes incoming
// events by tenant. Call Hub.Subscribe to attach SSE connections.
func NewHub(nc *nats.Conn) *Hub {
	h := &Hub{
		subs: make(map[uuid.UUID][]*subscriber),
	}
	if nc != nil {
		// ">" matches every subject at any depth — outbox topics are
		// dot-namespaced (e.g. "user.events", "auth", "group.events").
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

// Subscribe registers a new SSE consumer for tenantID and returns:
//   - ch: receive-only channel of ActivityEvent (buffered, subBufSize).
//   - unsubscribe: function the caller MUST invoke when the connection closes.
//
// The tenant is derived from the JWT principal in the SSE handler and is NEVER
// taken from the URL or request body.
func (h *Hub) Subscribe(tenantID uuid.UUID) (<-chan ActivityEvent, func()) {
	s := &subscriber{
		tenantID: tenantID,
		ch:       make(chan ActivityEvent, subBufSize),
	}

	h.mu.Lock()
	h.subs[tenantID] = append(h.subs[tenantID], s)
	h.mu.Unlock()

	return s.ch, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		list := h.subs[tenantID]
		for i, sub := range list {
			if sub == s {
				// Remove without preserving order — order is insertion order and
				// removal is O(n) over what is typically a tiny slice (< 10 SSE
				// connections per tenant in practice).
				h.subs[tenantID] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(h.subs[tenantID]) == 0 {
			delete(h.subs, tenantID)
		}
	}
}

// dispatch is the NATS message handler. It runs in NATS's internal goroutine so
// it must complete quickly: it extracts the tenant from the payload, maps the
// message to an ActivityEvent, and calls fanOut.
func (h *Hub) dispatch(msg *nats.Msg) {
	// The event type is carried in the Qeet-Event-Type header (set by
	// NATSPublisher.Publish). Skip messages without it (should never happen
	// in normal operation, but defensive).
	eventType := msg.Header.Get("Qeet-Event-Type")
	if eventType == "" {
		return
	}

	// Parse tenant_id from the payload. All domain events embed it. Events
	// without a tenant_id (e.g. platform system events) are skipped — they
	// have no tenant subscribers.
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

// fanOut delivers ev to every subscriber registered under tenantID.
// It is the critical per-tenant routing step: NO event is ever sent to a
// subscriber whose tenantID differs from ev's tenant.
//
// Drop-oldest policy: when a subscriber's channel is full, one buffered event
// is drained to make room, then the new event is enqueued. This avoids blocking
// the NATS dispatch goroutine and keeps slow consumers from affecting others.
func (h *Hub) fanOut(tenantID uuid.UUID, ev ActivityEvent) {
	h.mu.RLock()
	subs := h.subs[tenantID]
	h.mu.RUnlock()

	for _, s := range subs {
		select {
		case s.ch <- ev:
			// Fast path: channel had room.
		default:
			// Slow consumer — drop the oldest buffered event to make room.
			select {
			case <-s.ch:
			default:
			}
			// Best-effort re-enqueue; drop if channel is still full (very unlikely
			// because we just drained one slot, but guard against the race where
			// multiple goroutines are dispatching concurrently).
			select {
			case s.ch <- ev:
			default:
				slog.Warn("activity hub: event dropped (slow consumer)",
					"tenant_id", tenantID,
					"event_type", ev.Type,
				)
			}
		}
	}
}
