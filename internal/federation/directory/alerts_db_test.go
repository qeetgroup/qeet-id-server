//go:build integration

package directory

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAlertsCanBeListedChangedPausedAndRemoved checks the directory alert
// routes: a paused alert notifies nobody, changes and removals stay in the
// organization, and each is audited.
func TestAlertsCanBeListedChangedPausedAndRemoved(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, other := dbtest.Organization(test), dbtest.Organization(test)
	admin, otherAdmin := dbtest.User(test, organizationID, organizationID), dbtest.User(test, other, other)
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	as := func(user, organization uuid.UUID) http.Handler {
		return dbtest.Serve(dbtest.Principal(user, organization), (&Handler{Service: service}).Mount)
	}
	h := as(admin.ID, organizationID)
	base := "/organizations/" + organizationID.String() + "/directory/alerts"
	var alert Alert
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodPost, base, map[string]any{"name": "Any failure", "threshold": 1}), &alert)
	var list struct {
		Items []Alert `json:"items"`
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].ID != alert.ID || list.Items[0].UserID != admin.ID {
		test.Fatalf("list %+v, want the one alert, for its maker", list.Items)
	}

	if rec := dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		test.Fatalf("pause: %d %s", rec.Code, rec.Body.String())
	}
	if err := service.RecordOperation(ctx, organizationID, uuid.NewString(), "test", "connection", "", http.StatusBadGateway, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM auth.notifications WHERE organization_id=$1`, organizationID); n != 0 {
		test.Errorf("a paused alert sent %d notifications, want none", n)
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"threshold": 5, "name": "Bursts"}), &alert)
	if alert.Threshold != 5 || alert.Name != "Bursts" || alert.Enabled {
		test.Errorf("after changing: %+v, want threshold 5, renamed, still paused", alert)
	}
	if rec := dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"connection_id": uuid.NewString()}); rec.Code != http.StatusNotFound {
		test.Errorf("an unknown connection: %d, want 404", rec.Code)
	}
	otherBase := "/organizations/" + other.String() + "/directory/alerts/" + alert.ID.String()
	if rec := dbtest.Do(test, as(otherAdmin.ID, other), http.MethodDelete, otherBase, nil); rec.Code != http.StatusNotFound {
		test.Errorf("another organization removing the alert: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(test, h, http.MethodDelete, base+"/"+alert.ID.String(), nil); rec.Code != http.StatusNoContent {
		test.Errorf("remove: %d", rec.Code)
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 0 {
		test.Errorf("after removing: %+v, want none", list.Items)
	}
	for action, want := range map[string]int{"directory.alert_created": 1, "directory.alert_updated": 2, "directory.alert_deleted": 1} {
		if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE organization_id=$1 AND action=$2`, organizationID, action); n != want {
			test.Errorf("%d %s records, want %d", n, action, want)
		}
	}
}
