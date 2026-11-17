//go:build integration

package bot

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestBotSettingsChangesAreAudited checks that saving the bot-detection
// settings is recorded in the organization, as the administrator's, with each
// setting that changed from what was in force and the settings saved.
func TestBotSettingsChangesAreAudited(t *testing.T) {
	ctx := dbtest.Context(t)
	h := &Handler{Service: NewService(dbtest.Pool(t))}
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	as := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	path := "/tenants/" + organization.String() + "/security/bots/settings"
	type record struct {
		Changes  map[string]map[string]any `json:"changes"`
		Settings map[string]any            `json:"settings"`
	}
	recorded := func() []record {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE organization_id = $1 AND action = 'bot.settings_updated' AND resource_id = $1 AND actor_user_id = $2
			ORDER BY created_at`, organization, admin.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var raw []byte
			var r record
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}

	// From the defaults: the user-agent check off and a higher threshold.
	first := map[string]any{"ua_check": false, "honeypot": true, "captcha": false, "signature": false, "score_threshold": 0.9}
	if rec := dbtest.Do(t, as, http.MethodPut, path, first); rec.Code != http.StatusOK {
		t.Fatalf("save settings: %d %s", rec.Code, rec.Body.String())
	}
	got := recorded()
	want := map[string]map[string]any{
		"ua_check":        {"from": true, "to": false},
		"score_threshold": {"from": 0.7, "to": 0.9},
	}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Changes, want) || got[0].Settings["ua_check"] != false {
		t.Fatalf("recorded %+v, want one naming the user-agent check and threshold changes", got)
	}

	// From the saved row: only the captcha changes.
	second := map[string]any{"ua_check": false, "honeypot": true, "captcha": true, "signature": false, "score_threshold": 0.9}
	if rec := dbtest.Do(t, as, http.MethodPut, path, second); rec.Code != http.StatusOK {
		t.Fatalf("save settings again: %d %s", rec.Code, rec.Body.String())
	}
	got = recorded()
	if want := (map[string]map[string]any{"captcha": {"from": false, "to": true}}); len(got) != 2 || !reflect.DeepEqual(got[1].Changes, want) {
		t.Errorf("recorded %+v, want a second naming only the captcha", got)
	}
}
