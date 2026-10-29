//go:build integration

package user

import (
	"net/http"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestAPersonsSignInsAreSummarised checks that a member's sign-ins in the
// organisation over the period are counted by method, with those that met a
// second step, by address and browser, and their failures by reason, and that
// no one else's, nor older ones, count.
func TestAPersonsSignInsAreSummarised(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin, person, other := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	mac := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	iphone := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	insert := func(user any, action, ip, ua, meta, ago string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO audit.events (tenant_id, actor_type, actor_user_id, action, resource_type, ip, user_agent, metadata, created_at)
			VALUES ($1, 'user', $2, $3, 'session', $4::inet, $5, $6::jsonb, NOW() - $7::interval)`, tenant, user, action, ip, ua, meta, ago); err != nil {
			t.Fatal(err)
		}
	}
	insert(person.ID, "auth.login_succeeded", "198.51.100.1", mac, `{"method":"password","second_factor":"mfa"}`, "1 day")
	insert(person.ID, "auth.login_succeeded", "198.51.100.1", mac, `{"method":"password"}`, "2 days")
	insert(person.ID, "auth.login_succeeded", "203.0.113.9", iphone, `{"method":"passkey","second_factor":"passkey"}`, "3 days")
	insert(person.ID, "auth.login_succeeded", "203.0.113.9", iphone, `{"method":"password"}`, "60 days")
	insert(person.ID, "auth.sign_in_failed", "198.51.100.1", mac, `{"method":"password","reason":"wrong_password"}`, "1 day")
	insert(person.ID, "auth.sign_in_failed", "198.51.100.1", mac, `{"method":"password","reason":"wrong_password"}`, "1 day")
	insert(other.ID, "auth.login_succeeded", "192.0.2.4", mac, `{"method":"password"}`, "1 day")

	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Repo: NewRepository(pool), Validate: jsonNamedValidator()}).Mount)
	var got SignInSummary
	rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/users/"+person.ID.String()+"/sign-ins", nil)
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
	}
	if got.SignIns != 3 || got.WithSecondStep != 2 || len(got.ByMethod) != 2 || got.ByMethod[0] != (MethodCount{Method: "password", Count: 2, WithSecondStep: 1}) {
		t.Errorf("by method: %d sign-ins, %d with a second step, %+v", got.SignIns, got.WithSecondStep, got.ByMethod)
	}
	if len(got.ByAddress) != 2 || got.ByAddress[0].IP != "198.51.100.1" || got.ByAddress[0].Count != 2 {
		t.Errorf("by address: %+v", got.ByAddress)
	}
	if len(got.ByBrowser) != 2 || got.ByBrowser[0].Device != "Chrome on macOS" || got.ByBrowser[1].Kind != "mobile" {
		t.Errorf("by browser: %+v", got.ByBrowser)
	}
	if got.Failures != 2 || len(got.FailuresBy) != 1 || got.FailuresBy[0] != (FailureReason{Reason: "wrong_password", Count: 2}) {
		t.Errorf("failures: %d, %+v", got.Failures, got.FailuresBy)
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/users/"+person.ID.String()+"/sign-ins?days=90", nil), &got)
	if got.SignIns != 4 {
		t.Errorf("over 90 days: %d sign-ins, want 4", got.SignIns)
	}
	if rec := dbtest.Do(t, h, http.MethodGet, "/tenants/"+tenant.String()+"/users/"+person.ID.String()+"/sign-ins?days=400", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("400 days: %d, want 400", rec.Code)
	}
}
