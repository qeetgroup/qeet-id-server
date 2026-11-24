//go:build integration

package email

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

// TestSuppressionDetailStaysWithItsOrganization checks that an address suppressed by
// one organization's mail shows another only as suppressed, without the
// reason, the provider's detail or the date.
func TestSuppressionDetailStaysWithItsOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	store := delivery.NewStore(dbtest.Pool(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	address := dbtest.Unique("bounced") + "@example.test"
	providerID := dbtest.Unique("msg")
	if _, err := store.RecordSend(ctx, delivery.Record{OrganizationID: organizationA.String(), To: address, Template: "invite",
		Provider: "test", ProviderMessageID: providerID, Status: "sent"}); err != nil {
		t.Fatalf("record send: %v", err)
	}
	if err := store.Apply(ctx, delivery.Event{Provider: "test", ProviderMessageID: providerID, Status: "bounced",
		Reason: "550 mailbox unavailable", Suppress: []string{address}}); err != nil {
		t.Fatalf("apply bounce: %v", err)
	}

	suppression := func(organization uuid.UUID) map[string]any {
		t.Helper()
		var body struct {
			Suppression map[string]any `json:"suppression"`
		}
		admin := dbtest.User(t, organization, organization)
		h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&DeliveryHandler{Store: store}).Mount)
		rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/email/messages?to="+url.QueryEscape(address), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("messages: status %d (%s)", rec.Code, rec.Body.String())
		}
		dbtest.Decode(t, rec, &body)
		return body.Suppression
	}
	own := suppression(organizationA)
	if own["own"] != true || own["reason"] != "bounce" || own["detail"] == nil || own["id"] == nil {
		t.Errorf("the causing organization's view = %v, want its id, reason and detail", own)
	}
	other := suppression(organizationB)
	if other["own"] != false || len(other) != 1 {
		t.Errorf("another organization's view = %v, want only own: false", other)
	}
}

// TestMessagesPage checks the messages body: the page's items, next_cursor
// only while there is a next page, and a null suppression for an address
// that isn't suppressed.
func TestMessagesPage(t *testing.T) {
	ctx := dbtest.Context(t)
	store := delivery.NewStore(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	address := dbtest.Unique("delivered") + "@example.test"
	for range 3 {
		if _, err := store.RecordSend(ctx, delivery.Record{OrganizationID: organization.String(), To: address, Template: "invite",
			Provider: "test", ProviderMessageID: dbtest.Unique("msg"), Status: "sent"}); err != nil {
			t.Fatalf("record send: %v", err)
		}
	}
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&DeliveryHandler{Store: store}).Mount)
	page := func(query string) map[string]any {
		t.Helper()
		rec := dbtest.Do(t, h, http.MethodGet, "/organizations/"+organization.String()+"/email/messages?to="+url.QueryEscape(address)+query, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("messages%s: status %d (%s)", query, rec.Code, rec.Body.String())
		}
		var body map[string]any
		dbtest.Decode(t, rec, &body)
		return body
	}
	first := page("&limit=2")
	cursor, _ := first["next_cursor"].(string)
	if items, _ := first["items"].([]any); len(items) != 2 || cursor == "" {
		t.Fatalf("first page = %v, want 2 items and a next_cursor", first)
	}
	if s, ok := first["suppression"]; !ok || s != nil {
		t.Errorf("suppression = %v (present %v), want null", s, ok)
	}
	last := page("&limit=2&cursor=" + url.QueryEscape(cursor))
	if items, _ := last["items"].([]any); len(items) != 1 {
		t.Errorf("last page = %v, want 1 item", last)
	}
	if _, ok := last["next_cursor"]; ok {
		t.Errorf("the last page carries next_cursor: %v", last)
	}
}

// TestClearingASuppressionCommitsWithItsAuditEvent checks that lifting a
// suppression is undone when its audit event can't be written, and recorded
// once when it can.
func TestClearingASuppressionCommitsWithItsAuditEvent(t *testing.T) {
	ctx := dbtest.Context(t)
	store := delivery.NewStore(dbtest.Pool(t))
	h := &DeliveryHandler{Store: store}
	actor := audit.Actor{Type: "system"}
	// suppress bounces a send of the organization's and returns the suppression.
	suppress := func(organization uuid.UUID) uuid.UUID {
		t.Helper()
		address, providerID := dbtest.Unique("bounced")+"@example.test", dbtest.Unique("msg")
		if _, err := store.RecordSend(ctx, delivery.Record{OrganizationID: organization.String(), To: address, Template: "invite",
			Provider: "test", ProviderMessageID: providerID, Status: "sent"}); err != nil {
			t.Fatal(err)
		}
		if err := store.Apply(ctx, delivery.Event{Provider: "test", ProviderMessageID: providerID, Status: "bounced",
			Reason: "550 mailbox unavailable", Suppress: []string{address}}); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM platform.email_suppressions WHERE organization_id = $1`, organization).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	live := func(id uuid.UUID) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM platform.email_suppressions WHERE id = $1 AND cleared_at IS NULL`, id)
	}

	refused := dbtest.Organization(t)
	id := suppress(refused)
	refuseAudit(t, refused, "email.suppression_cleared")
	if err := h.clearSuppression(ctx, refused, id, actor); err == nil {
		t.Fatal("clear while its audit event can't be written: no error")
	}
	if live(id) != 1 {
		t.Error("the suppression was lifted without its audit event")
	}

	organization := dbtest.Organization(t)
	id = suppress(organization)
	if err := h.clearSuppression(ctx, organization, id, actor); err != nil {
		t.Fatal(err)
	}
	if live(id) != 0 || events(t, organization, "email.suppression_cleared") != 1 {
		t.Error("a cleared suppression: want it lifted and recorded once")
	}
}
