package activity

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// newTestEvent returns an ActivityEvent of the given type and severity, with a
// fresh ID and At set to now.
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

// TestHubTenantIsolation checks that an event for one tenant never reaches
// another tenant's subscriber.
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

// TestHubSlowConsumerDropOldest checks that a full subscriber channel drops its
// TestHubSlowConsumerIsToldItLostAnEvent checks that an event for a subscriber
// whose channel is full is dropped without blocking, and the subscriber told,
// once, that it lost one, so its stream can have the client catch up; the
// events already buffered stay.
func TestHubSlowConsumerIsToldItLostAnEvent(t *testing.T) {
	h := NewHub(nil)
	tenant := uuid.New()
	ch, lost, unsub := h.subscribe(tenant)
	defer unsub()

	for range subBufSize {
		h.fanOut(tenant, newTestEvent("user.created", SeveritySuccess))
	}
	select {
	case <-lost:
		t.Fatal("told it lost an event before its channel was full")
	default:
	}
	h.fanOut(tenant, newTestEvent("overflow", SeverityInfo)) // must not block
	h.fanOut(tenant, newTestEvent("overflow", SeverityInfo)) // nor signal twice
	select {
	case <-lost:
	default:
		t.Fatal("not told it lost an event")
	}
	if len(ch) != subBufSize {
		t.Errorf("%d events buffered, want the %d it had room for", len(ch), subBufSize)
	}
	for range subBufSize {
		if ev := <-ch; ev.Type == "overflow" {
			t.Fatal("an event past the full channel was delivered")
		}
	}
}

// TestHubUnsubscribeCleanup checks that unsubscribing removes the subscriber
// from the hub, and that a later fan-out to the tenant does not block.
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

// TestHubMultipleSubscribersSameTenant checks that every connection of a tenant
// receives each event.
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

// TestMapOutboxEventTenantID checks that mapOutboxEvent takes TenantID from its
// argument, not from the payload.
func TestMapOutboxEventTenantID(t *testing.T) {
	tenantID := uuid.New()
	otherID := uuid.New() // another UUID present in the payload — must not win
	payload := []byte(`{"tenant_id":"` + otherID.String() + `","id":"00000000-0000-0000-0000-000000000001"}`)

	ev := mapOutboxEvent("user.events", "user.created", tenantID, payload)

	if ev.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %v (must come from the caller-supplied tenantID)", ev.TenantID, tenantID)
	}
}

// TestMapAuditRowTenantID checks that mapAuditRow copies the row's TenantID.
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

// TestHubMisroutedEventDroppedAtWriteBoundary checks that an event forced into
// another tenant's channel keeps its own TenantID, so the stream handler's
// tenant check would drop it.
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

// TestCategoryOf checks categoryOf and severityOf against a sample of actions.
func TestCategoryOf(t *testing.T) {
	cases := []struct {
		action  string
		wantCat string
		wantSev string
	}{
		{"user.created", CategoryDirectory, SeveritySuccess},
		{"user.deleted", CategoryDirectory, SeverityWarning},
		{"auth.login.failed", CategoryAuthentication, SeverityError},
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

// TestHubFanOutDuringUnsubscribe checks that fanning out while other
// connections of the tenant subscribe and unsubscribe is free of data races.
// It is meaningful under the race detector.
func TestHubFanOutDuringUnsubscribe(t *testing.T) {
	h := NewHub(nil)
	tenant := uuid.New()
	for i := 0; i < 3; i++ {
		_, unsub := h.Subscribe(tenant)
		defer unsub()
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Removing the earlier of two subscribers shifts the later one down
			// in the slice fanOut reads.
			_, unsubFirst := h.Subscribe(tenant)
			_, unsubSecond := h.Subscribe(tenant)
			unsubFirst()
			unsubSecond()
		}
	}()
	ev := newTestEvent("user.created", SeveritySuccess)
	for i := 0; i < 2000; i++ {
		h.fanOut(tenant, ev)
	}
	close(stop)
	<-done
}
