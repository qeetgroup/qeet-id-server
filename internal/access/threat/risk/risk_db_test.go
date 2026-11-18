//go:build integration

package risk

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestRiskSettingsChangesAreAudited checks that saving the risk settings is
// recorded in the organization, as the administrator's, with each setting that
// changed from what was in force.
func TestRiskSettingsChangesAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	h := &Handler{Service: NewService(dbtest.Pool(t))}
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	path := "/organizations/" + organization.String() + "/security/risk-settings"
	changes := func() []map[string]map[string]any {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata->'changes' FROM audit.events
			WHERE organization_id = $1 AND action = 'risk.settings_updated' AND resource_id = $1 AND actor_user_id = $2
			ORDER BY created_at`, organization, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]map[string]any
		for rows.Next() {
			var raw []byte
			var c map[string]map[string]any
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}

	settings := map[string]any{"medium_threshold": 0.5, "high_threshold": 0.8, "force_mfa_at_level": "medium",
		"impossible_travel_enabled": true, "min_travel_hours": 3, "device_reputation_enabled": false}
	if rec := dbtest.Do(t, as, http.MethodPut, path, settings); rec.Code != http.StatusOK {
		t.Fatalf("save settings: %d %s", rec.Code, rec.Body.String())
	}
	settings["high_threshold"] = 0.9
	if rec := dbtest.Do(t, as, http.MethodPut, path, settings); rec.Code != http.StatusOK {
		t.Fatalf("save settings again: %d %s", rec.Code, rec.Body.String())
	}
	want := []map[string]map[string]any{
		{"force_mfa_at_level": {"from": "high", "to": "medium"}, "impossible_travel_enabled": {"from": false, "to": true}},
		{"high_threshold": {"from": 0.8, "to": 0.9}},
	}
	if got := changes(); !reflect.DeepEqual(got, want) {
		t.Errorf("recorded changes %v, want %v", got, want)
	}
}

// TestAssessDoesNotRecord checks that assessing a sign-in leaves the history
// unchanged, so a refused or challenged sign-in asked again is assessed the
// same, and that RecordSignIn adds a completed one.
func TestAssessDoesNotRecord(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	u := dbtest.User(t, organization, organization)
	history := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.login_context_history WHERE organization_id = $1 AND user_id = $2`, organization, u.ID)
	}

	first := svc.Assess(ctx, organization, u.ID, "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN")
	if again := svc.Assess(ctx, organization, u.ID, "192.0.2.1", "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN"); again != first {
		t.Errorf("the same sign-in assessed again = %v, first %v", again, first)
	}
	if n := history(); n != 0 {
		t.Fatalf("assessing recorded %d sign-ins", n)
	}
	svc.RecordSignIn(ctx, organization, u.ID, "Mozilla/5.0 (X11; Linux x86_64) Firefox/130.0", "IN")
	if n := history(); n != 1 {
		t.Errorf("RecordSignIn recorded %d sign-ins, want 1", n)
	}
}
