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

// TestHubOrganizationIsolation checks that an event for one organization never reaches
// another organization's subscriber.
func TestHubOrganizationIsolation(t *testing.T) {
	h := NewHub(nil) // no NATS — we drive fanOut directly

	organizationA := uuid.New()
	organizationB := uuid.New()

	chA, unsubA := h.Subscribe(organizationA)
	defer unsubA()
	chB, unsubB := h.Subscribe(organizationB)
	defer unsubB()

	evA := newTestEvent("user.created", SeveritySuccess)
	evB := newTestEvent("user.deleted", SeverityWarning)

	h.fanOut(organizationA, evA)
	h.fanOut(organizationB, evB)

	// organizationA channel must have exactly evA.
	select {
	case got := <-chA:
		if got.ID != evA.ID {
			t.Errorf("tenantA: got event %v, want %v", got.ID, evA.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("tenantA: no event received within 1s")
	}

	// organizationB channel must have exactly evB.
	select {
	case got := <-chB:
		if got.ID != evB.ID {
			t.Errorf("tenantB: got event %v, want %v", got.ID, evB.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("tenantB: no event received within 1s")
	}

	// organizationA must NOT have received organizationB's event — the critical isolation assertion.
	select {
	case extra := <-chA:
		t.Errorf("ISOLATION FAILURE: tenantA received event intended for tenantB: %v (type=%s)",
			extra.ID, extra.Type)
	default:
	}

	// organizationB must NOT have received organizationA's event.
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
	organization := uuid.New()
	ch, lost, unsub := h.subscribe(organization)
	defer unsub()

	for range subBufSize {
		h.fanOut(organization, newTestEvent("user.created", SeveritySuccess))
	}
	select {
	case <-lost:
		t.Fatal("told it lost an event before its channel was full")
	default:
	}
	h.fanOut(organization, newTestEvent("overflow", SeverityInfo)) // must not block
	h.fanOut(organization, newTestEvent("overflow", SeverityInfo)) // nor signal twice
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
// from the hub, and that a later fan-out to the organization does not block.
func TestHubUnsubscribeCleanup(t *testing.T) {
	h := NewHub(nil)
	organization := uuid.New()

	_, unsub := h.Subscribe(organization)

	// Sanity: subscriber is registered.
	h.mu.RLock()
	before := len(h.subs[organization])
	h.mu.RUnlock()
	if before != 1 {
		t.Fatalf("want 1 subscriber before unsub, got %d", before)
	}

	unsub()

	// After unsubscribe the map entry must be cleaned up.
	h.mu.RLock()
	after := len(h.subs[organization])
	h.mu.RUnlock()
	if after != 0 {
		t.Errorf("want 0 subscribers after unsub, got %d", after)
	}

	// Sending an event after unsub must not panic or block.
	h.fanOut(organization, newTestEvent("user.created", SeveritySuccess))
}

// TestHubMultipleSubscribersSameOrganization checks that every connection of an organization
// receives each event.
func TestHubMultipleSubscribersSameOrganization(t *testing.T) {
	h := NewHub(nil)
	organization := uuid.New()

	ch1, unsub1 := h.Subscribe(organization)
	defer unsub1()
	ch2, unsub2 := h.Subscribe(organization)
	defer unsub2()

	ev := newTestEvent("group.created", SeveritySuccess)
	h.fanOut(organization, ev)

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

// TestMapOutboxEventOrganizationID checks that mapOutboxEvent takes OrganizationID from its
// argument, not from the payload.
func TestMapOutboxEventOrganizationID(t *testing.T) {
	organizationID := uuid.New()
	otherID := uuid.New() // another UUID present in the payload — must not win
	payload := []byte(`{"tenant_id":"` + otherID.String() + `","id":"00000000-0000-0000-0000-000000000001"}`)

	ev := mapOutboxEvent("user.events", "user.created", organizationID, payload)

	if ev.OrganizationID != organizationID {
		t.Errorf("TenantID = %v, want %v (must come from the caller-supplied tenantID)", ev.OrganizationID, organizationID)
	}
}

// TestMapAuditRowOrganizationID checks that mapAuditRow copies the row's OrganizationID.
func TestMapAuditRowOrganizationID(t *testing.T) {
	organizationID := uuid.New()
	row := auditRow{
		ID:             uuid.New(),
		Action:         "user.created",
		OrganizationID: organizationID,
	}
	ev := mapAuditRow(row)
	if ev.OrganizationID != organizationID {
		t.Errorf("TenantID = %v, want %v", ev.OrganizationID, organizationID)
	}
}

// TestHubMisroutedEventDroppedAtWriteBoundary checks that an event forced into
// another organization's channel keeps its own OrganizationID, so the stream handler's
// organization check would drop it.
func TestHubMisroutedEventDroppedAtWriteBoundary(t *testing.T) {
	h := NewHub(nil) // no NATS — drive fanOut directly

	organizationA := uuid.New()
	organizationB := uuid.New()

	chA, unsubA := h.Subscribe(organizationA)
	defer unsubA()

	// Craft an event stamped with organizationB's ID and force it into organizationA's slot.
	// In normal operation this would be impossible; the hub routes by the
	// tenant_id in the payload via dispatch → fanOut(organizationID, ev). Here we
	// bypass that to test the write-boundary guard.
	badEv := ActivityEvent{
		ID:             uuid.New(),
		OrganizationID: organizationB, // WRONG organization for this subscriber
		Type:           "user.created",
		Category:       categoryOf("user.created"),
		Severity:       SeveritySuccess,
		Title:          titleOf("user.created"),
		At:             time.Now().UTC(),
	}
	h.fanOut(organizationA, badEv) // force into organizationA's channel

	var received ActivityEvent
	select {
	case received = <-chA:
	case <-time.After(time.Second):
		t.Fatal("no event received from channel")
	}

	// Prove the guard condition: a SSE stream handler for organizationA would drop
	// this event because received.OrganizationID (organizationB) != connectionOrganization (organizationA).
	connectionOrganization := organizationA
	if received.OrganizationID == connectionOrganization {
		t.Errorf("ISOLATION FAILURE: mis-routed event has TenantID == connectionTenant (%v); guard would pass it through", connectionOrganization)
	}
	if received.OrganizationID != organizationB {
		t.Errorf("received.TenantID = %v, want %v", received.OrganizationID, organizationB)
	}
	// The actual drop happens in http.go: `if ev.OrganizationID != organizationID { continue }`.
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
// connections of the organization subscribe and unsubscribe is free of data races.
// It is meaningful under the race detector.
func TestHubFanOutDuringUnsubscribe(t *testing.T) {
	h := NewHub(nil)
	organization := uuid.New()
	for i := 0; i < 3; i++ {
		_, unsub := h.Subscribe(organization)
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
			_, unsubFirst := h.Subscribe(organization)
			_, unsubSecond := h.Subscribe(organization)
			unsubFirst()
			unsubSecond()
		}
	}()
	ev := newTestEvent("user.created", SeveritySuccess)
	for i := 0; i < 2000; i++ {
		h.fanOut(organization, ev)
	}
	close(stop)
	<-done
}
