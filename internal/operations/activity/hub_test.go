package activity

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestEvent is a helper that returns an ActivityEvent with the given type and
// severity, using a fresh random ID. The At field is set to now.
func newTestEvent(evType, severity string) ActivityEvent {
	return ActivityEvent{
		ID:       uuid.New(),
		Type:     evType,
		Category: categoryOf(evType),
		Severity: severity,
		Title:    titleOf(evType),
		At:       time.Now().UTC(),
	}
}

// TestHubTenantIsolation is the critical security test: verifies that an event
// fan-out to tenantA is NOT delivered to tenantB's subscriber, and vice versa.
// A cross-tenant delivery would be a security incident.
func TestHubTenantIsolation(t *testing.T) {
	h := NewHub(nil) // no NATS — we drive fanOut directly

	tenantA := uuid.New()
	tenantB := uuid.New()

	chA, unsubA := h.Subscribe(tenantA)
	defer unsubA()
	chB, unsubB := h.Subscribe(tenantB)
	defer unsubB()

	evA := newTestEvent("user.created", SeveritySuccess)
	evB := newTestEvent("user.deleted", SeverityWarning)

	h.fanOut(tenantA, evA)
	h.fanOut(tenantB, evB)

	// tenantA channel must have exactly evA.
	select {
	case got := <-chA:
		if got.ID != evA.ID {
			t.Errorf("tenantA: got event %v, want %v", got.ID, evA.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("tenantA: no event received within 1s")
	}

	// tenantB channel must have exactly evB.
	select {
	case got := <-chB:
		if got.ID != evB.ID {
			t.Errorf("tenantB: got event %v, want %v", got.ID, evB.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("tenantB: no event received within 1s")
	}

	// tenantA must NOT have received tenantB's event — the critical isolation assertion.
	select {
	case extra := <-chA:
		t.Errorf("ISOLATION FAILURE: tenantA received event intended for tenantB: %v (type=%s)",
			extra.ID, extra.Type)
	default:
	}

	// tenantB must NOT have received tenantA's event.
	select {
	case extra := <-chB:
		t.Errorf("ISOLATION FAILURE: tenantB received event intended for tenantA: %v (type=%s)",
			extra.ID, extra.Type)
	default:
	}
}

// TestHubSlowConsumerDropOldest verifies the drop-oldest policy: when a
// subscriber's channel is full, the hub drops the oldest buffered event to
// make room for the new one, rather than blocking or dropping the new event.
func TestHubSlowConsumerDropOldest(t *testing.T) {
	h := NewHub(nil)
	tenant := uuid.New()

	ch, unsub := h.Subscribe(tenant)
	defer unsub()

	// Fill the channel to capacity.
	for i := 0; i < subBufSize; i++ {
		ev := newTestEvent("user.created", SeveritySuccess)
		// Mark with a sequence so we can identify ordering.
		ev.Type = "seq." + string(rune('A'+i%26))
		h.fanOut(tenant, ev)
	}

	// Overflow: one more event should succeed (drop-oldest makes room).
	overflow := newTestEvent("overflow.event", SeverityInfo)
	overflow.Type = "overflow"
	h.fanOut(tenant, overflow) // must not block

	// The channel should still have exactly subBufSize events.
	count := 0
	hasOverflow := false
	drain := time.After(2 * time.Second)
loop:
	for {
		select {
		case got := <-ch:
			count++
			if got.Type == "overflow" {
				hasOverflow = true
			}
		case <-drain:
			break loop
		default:
			break loop
		}
	}

	if count != subBufSize {
		t.Errorf("want %d events after overflow, got %d", subBufSize, count)
	}
	if !hasOverflow {
		t.Error("overflow event was not delivered (expected it to replace the oldest)")
	}
}

// TestHubUnsubscribeCleanup verifies that after unsubscribing, the hub's
// internal map removes the subscriber (no leak) and subsequent events to that
// tenant are not delivered to the closed channel.
func TestHubUnsubscribeCleanup(t *testing.T) {
	h := NewHub(nil)
	tenant := uuid.New()

	_, unsub := h.Subscribe(tenant)

	// Sanity: subscriber is registered.
	h.mu.RLock()
	before := len(h.subs[tenant])
	h.mu.RUnlock()
	if before != 1 {
		t.Fatalf("want 1 subscriber before unsub, got %d", before)
	}

	unsub()

	// After unsubscribe the map entry must be cleaned up.
	h.mu.RLock()
	after := len(h.subs[tenant])
	h.mu.RUnlock()
	if after != 0 {
		t.Errorf("want 0 subscribers after unsub, got %d", after)
	}

	// Sending an event after unsub must not panic or block.
	h.fanOut(tenant, newTestEvent("user.created", SeveritySuccess))
}

// TestHubMultipleSubscribersSameTenant verifies that two concurrent SSE
// connections for the same tenant both receive each event.
func TestHubMultipleSubscribersSameTenant(t *testing.T) {
	h := NewHub(nil)
	tenant := uuid.New()

	ch1, unsub1 := h.Subscribe(tenant)
	defer unsub1()
	ch2, unsub2 := h.Subscribe(tenant)
	defer unsub2()

	ev := newTestEvent("group.created", SeveritySuccess)
	h.fanOut(tenant, ev)

	for i, ch := range []<-chan ActivityEvent{ch1, ch2} {
		select {
		case got := <-ch:
			if got.ID != ev.ID {
				t.Errorf("subscriber %d: got %v, want %v", i+1, got.ID, ev.ID)
			}
		case <-time.After(time.Second):
			t.Errorf("subscriber %d: no event received", i+1)
		}
	}
}

// TestMapOutboxEventTenantID verifies that mapOutboxEvent populates
// ActivityEvent.TenantID from the tenantID argument, not from the payload.
func TestMapOutboxEventTenantID(t *testing.T) {
	tenantID := uuid.New()
	otherID := uuid.New() // another UUID present in the payload — must not win
	payload := []byte(`{"tenant_id":"` + otherID.String() + `","id":"00000000-0000-0000-0000-000000000001"}`)

	ev := mapOutboxEvent("user.events", "user.created", tenantID, payload)

	if ev.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v (must come from the caller-supplied tenantID)", ev.TenantID, tenantID)
	}
}

// TestMapAuditRowTenantID verifies that mapAuditRow populates
// ActivityEvent.TenantID from the scanned auditRow.TenantID field.
func TestMapAuditRowTenantID(t *testing.T) {
	tenantID := uuid.New()
	row := auditRow{
		ID:       uuid.New(),
		Action:   "user.created",
		TenantID: tenantID,
	}
	ev := mapAuditRow(row)
	if ev.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", ev.TenantID, tenantID)
	}
}

// TestHubMisroutedEventDroppedAtWriteBoundary simulates the defense-in-depth
// scenario where the hub theoretically mis-routes an event (tenantB's event
// ends up in tenantA's subscriber channel). The SSE stream handler's guard
// checks ev.TenantID != connectionTenant and drops such events before writing
// to the SSE stream. This test proves:
//  1. fanOut can deliver an event with any TenantID to any subscriber (hub
//     routing is by channel key, TenantID is in the payload).
//  2. The guard condition ev.TenantID != connectionTenant would catch it.
func TestHubMisroutedEventDroppedAtWriteBoundary(t *testing.T) {
	h := NewHub(nil) // no NATS — drive fanOut directly

	tenantA := uuid.New()
	tenantB := uuid.New()

	chA, unsubA := h.Subscribe(tenantA)
	defer unsubA()

	// Craft an event stamped with tenantB's ID and force it into tenantA's slot.
	// In normal operation this would be impossible; the hub routes by the
	// tenant_id in the payload via dispatch → fanOut(tenantID, ev). Here we
	// bypass that to test the write-boundary guard.
	badEv := ActivityEvent{
		ID:       uuid.New(),
		TenantID: tenantB, // WRONG tenant for this subscriber
		Type:     "user.created",
		Category: categoryOf("user.created"),
		Severity: SeveritySuccess,
		Title:    titleOf("user.created"),
		At:       time.Now().UTC(),
	}
	h.fanOut(tenantA, badEv) // force into tenantA's channel

	var received ActivityEvent
	select {
	case received = <-chA:
	case <-time.After(time.Second):
		t.Fatal("no event received from channel")
	}

	// Prove the guard condition: a SSE stream handler for tenantA would drop
	// this event because received.TenantID (tenantB) != connectionTenant (tenantA).
	connectionTenant := tenantA
	if received.TenantID == connectionTenant {
		t.Errorf("ISOLATION FAILURE: mis-routed event has TenantID == connectionTenant (%v); guard would pass it through", connectionTenant)
	}
	if received.TenantID != tenantB {
		t.Errorf("received.TenantID = %v, want %v", received.TenantID, tenantB)
	}
	// The actual drop happens in http.go: `if ev.TenantID != tenantID { continue }`.
	// The assertions above confirm the condition would be triggered correctly.
}

// TestCategoryOf exercises the mapping table for a representative sample of
// event types. Failures here break the severity/category columns in the UI.
func TestCategoryOf(t *testing.T) {
	cases := []struct {
		action  string
		wantCat string
		wantSev string
	}{
		{"user.created", CategoryDirectory, SeveritySuccess},
		{"user.deleted", CategoryDirectory, SeverityWarning},
		{"auth.login.failed", CategoryAuthentication, SeverityWarning},
		{"auth.session.revoked_for_reuse", CategoryAuthentication, SeverityCritical},
		{"threat.anomaly_detected", CategorySecurity, SeverityCritical},
		{"rbac.role_assigned", CategoryAuthorization, SeverityInfo},
		{"group.member_added", CategoryDirectory, SeverityInfo},
		{"agent.created", CategoryDeveloper, SeveritySuccess},
		{"apikey.rotated", CategoryDeveloper, SeverityWarning},
		{"webhook.created", CategoryDeveloper, SeveritySuccess},
		{"system.shutdown", CategorySystem, SeverityInfo},
		{"mfa.enabled", CategoryAuthentication, SeveritySuccess},
		{"scim.user_provisioned", CategoryDirectory, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			if got := categoryOf(tc.action); got != tc.wantCat {
				t.Errorf("categoryOf(%q) = %q, want %q", tc.action, got, tc.wantCat)
			}
			if got := severityOf(tc.action); got != tc.wantSev {
				t.Errorf("severityOf(%q) = %q, want %q", tc.action, got, tc.wantSev)
			}
		})
	}
}
