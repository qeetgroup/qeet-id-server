//go:build integration

package webhook

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	sub := subscribe(t, svc, organization, endpoint.URL, "group.created")
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	base := "/organizations/" + organization.String() + "/webhooks/" + sub.ID.String()

	strict := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: testService(t)}).Mount) // public addresses only
	if rec := dbtest.Do(t, strict, http.MethodPatch, base, map[string]any{"url": "http://10.0.0.1/hook"}); !strings.Contains(rec.Body.String(), CodeURLNotAllowed) {
		t.Errorf("change to a private address: %d %s, want %s", rec.Code, rec.Body.String(), CodeURLNotAllowed)
	}
	var changed Subscription
	rec := dbtest.Do(t, h, http.MethodPatch, base, map[string]any{"events": []string{"group.created", "group.deleted"}})
	dbtest.Decode(t, rec, &changed)
	if rec.Code != http.StatusOK || len(changed.Events) != 2 || changed.URL != endpoint.URL {
		t.Fatalf("change the events: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'webhook.subscription_updated' AND metadata->'changes' ? 'events'`, organization); n != 1 {
		t.Errorf("the change was audited %d times, want once with what changed", n)
	}

	dispatch(t, svc, groupCreated(organization), groupCreated(organization))
	refuse.Store(true)
	dispatch(t, svc, groupCreated(organization))

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
	last := dbtest.Do(t, h, http.MethodGet, "/webhooks/"+sub.ID.String()+"/deliveries?limit=2&cursor="+page.NextCursor, nil)
	page.NextCursor = ""
	dbtest.Decode(t, last, &page)
	if len(page.Items) != 1 || strings.Contains(last.Body.String(), "next_cursor") {
		t.Errorf("second page: %d items, %s; want the last one and no next_cursor", len(page.Items), last.Body.String())
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

// refuseAudit makes the database refuse organization's audit rows of action
// until t ends, as a failing audit write would.
func refuseAudit(t *testing.T, organization uuid.UUID, action string) {
	t.Helper()
	ctx, owner := dbtest.Context(t), dbtest.Owner(t)
	name := "refuse_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	for _, sql := range []string{
		`CREATE FUNCTION audit.` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused'; END $$`,
		fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON audit.events FOR EACH ROW
			WHEN (NEW.organization_id = '%s' AND NEW.action = '%s') EXECUTE FUNCTION audit.%s()`, name, organization, action, name),
	} {
		if _, err := owner.Exec(ctx, sql); err != nil {
			t.Fatalf("refuse %s: %v", action, err)
		}
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `DROP TRIGGER `+name+` ON audit.events; DROP FUNCTION audit.`+name+`()`)
	})
}

// TestWebhookChangesCommitWithTheirAudit checks that each change to a webhook
// over HTTP is audited as the caller's, and that one whose audit row can't be
// written is refused and leaves the webhook as it was.
func TestWebhookChangesCommitWithTheirAudit(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := dispatchService(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Service: svc}).Mount)
	rec := dbtest.Do(t, h, http.MethodPost, "/webhooks", map[string]any{"url": "https://hooks.example.test/a", "events": []string{"group.created"}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var sub Subscription
	dbtest.Decode(t, rec, &sub)
	base := "/organizations/" + organization.String() + "/webhooks/" + sub.ID.String()
	changes := []struct {
		method, path, action string
		body                 any
	}{
		{http.MethodPatch, base, "webhook.subscription_updated", map[string]any{"events": []string{"group.created", "group.deleted"}}},
		{http.MethodPost, base + "/rotate-secret", "webhook.secret_rotated", nil},
		{http.MethodPost, base + "/deliveries/retry", "webhook.deliveries_retried", nil},
		{http.MethodDelete, "/webhooks/" + sub.ID.String(), "webhook.subscription_disabled", nil},
		{http.MethodPost, base + "/enable", "webhook.subscription_enabled", nil},
	}
	for _, c := range changes {
		if rec := dbtest.Do(t, h, c.method, c.path, c.body); rec.Code/100 != 2 {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	for _, action := range []string{"webhook.subscription_created", "webhook.subscription_updated", "webhook.secret_rotated",
		"webhook.deliveries_retried", "webhook.subscription_disabled", "webhook.subscription_enabled"} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2
			AND resource_type = 'webhook_subscription' AND resource_id = $3 AND actor_user_id = $4`, organization, action, sub.ID, admin.ID); n != 1 {
			t.Errorf("%s: %d audit rows as the admin, want 1", action, n)
		}
	}

	state := func() string {
		t.Helper()
		var s string
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT events::text || encode(secret_ct, 'hex') || (disabled_at IS NULL)::text
			FROM organization.webhook_subscriptions WHERE id = $1 AND organization_id = $2`, sub.ID, organization).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	refuseAudit(t, organization, "webhook.subscription_created")
	for _, c := range changes {
		refuseAudit(t, organization, c.action)
	}
	before := state()
	if rec := dbtest.Do(t, h, http.MethodPost, "/webhooks", map[string]any{"url": "https://hooks.example.test/b", "events": []string{"group.created"}}); rec.Code != http.StatusInternalServerError {
		t.Errorf("create with its audit refused: %d %s, want 500", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.webhook_subscriptions WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d subscriptions after a creation that wasn't audited, want 1", n)
	}
	changes[0].body = map[string]any{"events": []string{"user.created"}}
	for _, c := range changes[:4] {
		if rec := dbtest.Do(t, h, c.method, c.path, c.body); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s %s with its audit refused: %d %s, want 500", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if after := state(); after != before {
		t.Errorf("changes that weren't audited were kept: %s, was %s", after, before)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.webhook_subscriptions SET disabled_at = NOW(), disabled_reason = 'disabled'
		WHERE id = $1 AND organization_id = $2`, sub.ID, organization); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, base+"/enable", nil); rec.Code != http.StatusInternalServerError {
		t.Errorf("enable with its audit refused: %d %s, want 500", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.webhook_subscriptions WHERE id = $1 AND organization_id = $2 AND disabled_at IS NOT NULL`,
		sub.ID, organization); n != 1 {
		t.Error("an enabling that wasn't audited was kept")
	}
}
