//go:build integration

package analytics

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestSignInsAreTrendedOverAChosenRange checks that the overview, asked for a
// range, counts each UTC day's sign-ins, the people who signed in and the
// failures, by one method when asked, leaving out organization switches.
func TestSignInsAreTrendedOverAChosenRange(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	admin, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	insert := func(user any, action, method, ago string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO audit.events (organization_id, actor_type, actor_user_id, action, resource_type, metadata, created_at)
			VALUES ($1, 'user', $2, $3, 'session', jsonb_build_object('method', $4::text), date_trunc('day', NOW()) + INTERVAL '1 hour' - $5::interval)`,
			organization, user, action, method, ago); err != nil {
			t.Fatal(err)
		}
	}
	insert(admin.ID, "auth.login_succeeded", "password", "2 days")
	insert(admin.ID, "auth.login_succeeded", "password", "2 days")
	insert(other.ID, "auth.login_succeeded", "passkey", "2 days")
	insert(other.ID, "auth.sign_in_failed", "password", "1 day")
	insert(admin.ID, "auth.login_succeeded", "tenant_switch", "1 day")
	insert(admin.ID, "auth.login_succeeded", "password", "40 days")

	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Reader: NewReader(pool)}).Mount)
	var out Overview
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/analytics/overview?days=3", nil), &out)
	if out.Range == nil || len(out.Range.Days) != 4 {
		t.Fatalf("range %+v, want four days", out.Range)
	}
	if d := out.Range.Days[1]; d.SignIns != 3 || d.People != 2 || d.Failed != 0 {
		t.Errorf("two days ago: %+v, want 3 sign-ins by 2 people", d)
	}
	if d := out.Range.Days[2]; d.SignIns != 0 || d.Failed != 1 {
		t.Errorf("yesterday: %+v, want the failure and no switch", d)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/analytics/overview?days=3&method=passkey", nil), &out)
	if d := out.Range.Days[1]; d.SignIns != 1 || d.People != 1 {
		t.Errorf("passkey sign-ins two days ago: %+v, want 1", d)
	}
	var plain Overview
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/analytics/overview", nil), &plain)
	if plain.Range != nil {
		t.Error("an overview asked for no range carries one")
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+organization.String()+"/analytics/overview?days=500", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("500 days: %d, want 400", rec.Code)
	}
}
