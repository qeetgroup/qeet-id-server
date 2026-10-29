//go:build integration

package webhook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAWebhookIsChangedAndItsDeliveriesFollowed checks that a webhook's URL
// and events can be changed, with a coded refusal for a disallowed address;
// that each delivery attempt is kept with its answer and time; that the
// webhook shows its last delivery and how many deliveries are pending,
// retrying and given up; that deliveries page by cursor and filter by status;
// that given-up ones can be sent again together; and that disabling names who
// did it.
func TestAWebhookIsChangedAndItsDeliveriesFollowed(t *testing.T) {
	var refuse atomic.Bool
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if refuse.Load() {
			w.WriteHeader(http.StatusGone)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer endpoint.Close()
	svc := dispatchService(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	sub := subscribe(t, svc, tenant, endpoint.URL, "group.created")
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: svc}).Mount)
	base := "/tenants/" + tenant.String() + "/webhooks/" + sub.ID.String()

	strict := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: NewService(dbtest.Pool(t))}).Mount) // public addresses only
	if rec := dbtest.Do(t, strict, http.MethodPatch, base, map[string]any{"url": "http://10.0.0.1/hook"}); !strings.Contains(rec.Body.String(), errs.CodeWebhookURLNotAllowed) {
		t.Errorf("change to a private address: %d %s, want %s", rec.Code, rec.Body.String(), errs.CodeWebhookURLNotAllowed)
	}
	var changed Subscription
	rec := dbtest.Do(t, h, http.MethodPatch, base, map[string]any{"events": []string{"group.created", "group.deleted"}})
	dbtest.Decode(t, rec, &changed)
	if rec.Code != http.StatusOK || len(changed.Events) != 2 || changed.URL != endpoint.URL {
		t.Fatalf("change the events: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'webhook.subscription_updated' AND metadata->'changes' ? 'events'`, tenant); n != 1 {
		t.Errorf("the change was audited %d times, want once with what changed", n)
	}

	dispatch(t, svc, groupCreated(tenant), groupCreated(tenant))
	refuse.Store(true)
	dispatch(t, svc, groupCreated(tenant))

	var got Subscription
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String(), nil), &got)
	if got.LastDeliveredAt == nil || got.LastStatusCode == nil || got.Counts == nil || got.Counts.GaveUp != 1 || got.Counts.Pending != 0 {
		t.Errorf("webhook %+v counts %+v, want its last delivery and one given up", got, got.Counts)
	}
	var page struct {
		Items      []Delivery `json:"items"`
		NextCursor string     `json:"next_cursor"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String()+"/deliveries?limit=2", nil), &page)
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %d, cursor %q", len(page.Items), page.NextCursor)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String()+"/deliveries?limit=2&cursor="+page.NextCursor, nil), &page)
	if len(page.Items) != 1 || page.NextCursor != "" {
		t.Errorf("second page: %d, cursor %q", len(page.Items), page.NextCursor)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String()+"/deliveries?status=dead", nil), &page)
	if len(page.Items) != 1 {
		t.Fatalf("dead deliveries: %d, want 1", len(page.Items))
	}
	dead := page.Items[0]
	var attempts struct {
		Items []Attempt `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/deliveries/"+dead.ID.String()+"/attempts", nil), &attempts)
	if len(attempts.Items) != 1 || attempts.Items[0].StatusCode == nil || *attempts.Items[0].StatusCode != http.StatusGone || attempts.Items[0].DurationMS < 0 {
		t.Errorf("attempts %+v, want the one refused", attempts.Items)
	}

	refuse.Store(false)
	var retried struct {
		Requeued int `json:"requeued"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodPost, base+"/deliveries/retry", nil), &retried)
	if retried.Requeued != 1 {
		t.Errorf("retry given-up deliveries: %d, want 1", retried.Requeued)
	}
	dispatch(t, svc)
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, base+"/deliveries/"+dead.ID.String()+"/attempts", nil), &attempts)
	if len(attempts.Items) != 2 || *attempts.Items[1].StatusCode != http.StatusOK {
		t.Errorf("attempts after the retry: %+v, want the refusal then the delivery", attempts.Items)
	}

	if rec := dbtest.Do(t, h, http.MethodDelete, "/webhooks/"+sub.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("disable: %d", rec.Code)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String(), nil), &got)
	if got.DisabledBy == nil || *got.DisabledBy != admin.ID {
		t.Errorf("disabled by %v, want the admin", got.DisabledBy)
	}
}
