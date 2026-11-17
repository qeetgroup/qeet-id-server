//go:build integration

package policy

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestPatchChangesOnlyWhatItSends checks that a PATCH of the security policy
// changes the fields it names and keeps the rest, that null clears a nullable
// field, that an invalid change is refused and stores nothing, and that each
// change is audited.
func TestPatchChangesOnlyWhatItSends(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&Handler{Repo: NewRepository(dbtest.Pool(t))}).Mount)
	path := "/tenants/" + organization.String() + "/policy"
	read := func() Policy {
		t.Helper()
		var p Policy
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, path, nil), &p)
		return p
	}

	if rec := dbtest.Do(t, h, http.MethodPut, path, map[string]any{"mfa_enforcement": "required", "mfa_grace_days": 7, "max_sessions": 5}); rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, path, map[string]any{"max_sessions": 3}); rec.Code != http.StatusOK {
		t.Fatalf("patch max_sessions: %d %s", rec.Code, rec.Body.String())
	}
	p := read()
	if p.MFAEnforcement != "required" || p.MFAGraceDays != 7 || p.MaxSessions == nil || *p.MaxSessions != 3 {
		t.Errorf("after patching max_sessions: %+v; want it 3 and MFA kept", p)
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, path, map[string]any{"session_max_age": "48h"}); rec.Code != http.StatusOK {
		t.Fatalf("patch session_max_age: %d %s", rec.Code, rec.Body.String())
	}
	p = read()
	if time.Duration(p.SessionMaxAge) != 48*time.Hour || p.MaxSessions == nil || *p.MaxSessions != 3 || p.MFAEnforcement != "required" {
		t.Errorf("after patching session_max_age: %+v; want 48h and the rest kept", p)
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, path, map[string]any{"max_sessions": nil}); rec.Code != http.StatusOK {
		t.Fatalf("patch max_sessions null: %d %s", rec.Code, rec.Body.String())
	}
	if p = read(); p.MaxSessions != nil {
		t.Errorf("after clearing max_sessions: %v, want no limit", *p.MaxSessions)
	}
	if rec := dbtest.Do(t, h, http.MethodPatch, path, map[string]any{"mfa_grace_days": 500}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("an out-of-range grace period: %d, want 422", rec.Code)
	}
	if p = read(); p.MFAGraceDays != 7 {
		t.Errorf("a refused patch changed the grace period to %d", p.MFAGraceDays)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'security_policy.updated'`, organization); n != 4 {
		t.Errorf("%d policy changes audited, want 4", n)
	}
}
