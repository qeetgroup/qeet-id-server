//go:build integration

package authpolicy

import (
	"net/http"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPatchChangesOnlyWhatItSends checks that a PATCH of the security policy
// changes the fields it names and keeps the rest, that null clears a nullable
// field, that an invalid change is refused and stores nothing, and that each
// change is audited.
func TestPatchChangesOnlyWhatItSends(t *testing.T) {
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	h := dbtest.Serve(dbtest.Principal(admin.ID, organization), (&SecurityPolicyHandler{Repo: NewSecurityPolicies(dbtest.Pool(t), 0, 0)}).Mount)
	path := "/organizations/" + organization.String() + "/policy"
	read := func() SecurityPolicy {
		t.Helper()
		var p SecurityPolicy
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

// TestPolicyChangeCommitsWithItsAudit checks that a policy change and its
// audit row commit together: a stored change is recorded as its actor's, from
// where they made it, and a change whose audit row can't be written is not
// stored.
func TestPolicyChangeCommitsWithItsAudit(t *testing.T) {
	ctx := dbtest.Context(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	repo := NewSecurityPolicies(dbtest.Pool(t), 0, 0)
	by := audit.Actor{UserID: &admin.ID, Type: "user", IP: "203.0.113.5", UserAgent: "policy-test", RequestID: dbtest.Unique("request")}

	if _, err := repo.Replace(ctx, organization, SecurityPolicy{MFAEnforcement: "required"}, by); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'security_policy.updated'
		AND actor_user_id = $2 AND actor_type = 'user' AND resource_id = $1
		AND host(ip) = '203.0.113.5' AND user_agent = 'policy-test' AND request_id = $3`, organization, admin.ID, by.RequestID); n != 1 {
		t.Errorf("%d audit rows name the change's actor and request, want 1", n)
	}

	unrecordable := by
	unrecordable.IP = "not an address"
	if _, err := repo.Patch(ctx, organization, func(p *SecurityPolicy) error { p.MFAEnforcement = "optional"; return nil }, unrecordable); err == nil {
		t.Fatal("a change whose audit row failed was accepted")
	}
	if p, err := repo.Get(ctx, organization); err != nil || p.MFAEnforcement != "required" {
		t.Errorf("after a change that couldn't be audited the policy is %+v (%v); want it unchanged", p, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'security_policy.updated'`, organization); n != 1 {
		t.Errorf("%d policy changes audited, want 1", n)
	}
}
