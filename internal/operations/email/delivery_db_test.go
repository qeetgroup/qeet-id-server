//go:build integration

package email

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/delivery"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestSuppressionDetailStaysWithItsTenant checks that an address suppressed by
// one organisation's mail shows another only as suppressed, without the
// reason, the provider's detail or the date.
func TestSuppressionDetailStaysWithItsTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	store := delivery.NewStore(dbtest.Pool(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	address := dbtest.Unique("bounced") + "@example.test"
	providerID := dbtest.Unique("msg")
	if _, err := store.RecordSend(ctx, delivery.Record{TenantID: tenantA.String(), To: address, Template: "invite",
		Provider: "test", ProviderMessageID: providerID, Status: "sent"}); err != nil {
		t.Fatalf("record send: %v", err)
	}
	if err := store.Apply(ctx, delivery.Event{Provider: "test", ProviderMessageID: providerID, Status: "bounced",
		Reason: "550 mailbox unavailable", Suppress: []string{address}}); err != nil {
		t.Fatalf("apply bounce: %v", err)
	}

	suppression := func(tenant uuid.UUID) map[string]any {
		t.Helper()
		var body struct {
			Suppression map[string]any `json:"suppression"`
		}
		admin := dbtest.User(t, tenant, tenant)
		h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&DeliveryHandler{Store: store}).Mount)
		rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/email/messages?to="+url.QueryEscape(address), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("messages: status %d (%s)", rec.Code, rec.Body.String())
		}
		dbtest.Decode(t, rec, &body)
		return body.Suppression
	}
	own := suppression(tenantA)
	if own["own"] != true || own["reason"] != "bounce" || own["detail"] == nil || own["id"] == nil {
		t.Errorf("the causing organisation's view = %v, want its id, reason and detail", own)
	}
	other := suppression(tenantB)
	if other["own"] != false || len(other) != 1 {
		t.Errorf("another organisation's view = %v, want only own: false", other)
	}
}
