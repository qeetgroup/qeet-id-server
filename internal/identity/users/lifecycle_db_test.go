//go:build integration

package user

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// suspendedPage reads the caller's suspended-accounts list at query.
func suspendedPage(t *testing.T, h http.Handler, query string) SuspendedPage {
	t.Helper()
	rec := dbtest.Do(t, h, http.MethodGet, "/users/suspended"+query, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list suspended accounts%s: status %d (%s)", query, rec.Code, rec.Body.String())
	}
	var page SuspendedPage
	dbtest.Decode(t, rec, &page)
	return page
}

// listed returns the suspended account with id on page, if it is there.
func listed(page SuspendedPage, id uuid.UUID) (SuspendedUser, bool) {
	i := slices.IndexFunc(page.Items, func(u SuspendedUser) bool { return u.ID == id })
	if i < 0 {
		return SuspendedUser{}, false
	}
	return page.Items[i], true
}

// TestSuspensionEndsSessionsAndIsReviewed checks that suspending a person ends
// their sessions and records it once, that the suspension is listed and
// reviewed, that the person can't reactivate themselves, and that another
// organisation sees a suspension it doesn't manage without its details.
func TestSuspensionEndsSessionsAndIsReviewed(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	target := dbtest.User(t, tenant, tenant)
	session(t, target.ID, tenant, "")
	session(t, target.ID, nil, "")
	guest := dbtest.User(t, other, other, tenant)
	exec(t, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, guest.ID)
	exec(t, `UPDATE "user".users SET suspension_reason = 'account_compromise', suspension_risk = 'high' WHERE id = $1`, guest.ID)
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	path := "/users/" + target.ID.String()

	for range 2 {
		rec := dbtest.Do(t, as, http.MethodPatch, path, map[string]any{"status": "suspended"})
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"suspended"`) {
			t.Fatalf("suspend: %d %s", rec.Code, rec.Body.String())
		}
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("%d sessions are still live after the suspension", n)
	}
	if n := audited(t, tenant, "user.suspended", target.ID); n != 1 {
		t.Errorf("suspending twice recorded %d user.suspended audit events, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'user.suspended'`, target.ID); n != 1 {
		t.Errorf("%d user.suspended events, want 1", n)
	}

	page := suspendedPage(t, as, "")
	got, ok := listed(page, target.ID)
	if !ok || !got.CanManage || got.Source != "manual" || got.Review != "pending" || got.SuspendedAt == nil {
		t.Errorf("the suspension is listed as %+v (listed %t), want a manual one pending review that the organisation manages", got, ok)
	}
	if page.Summary.Manual != 1 || page.Summary.Pending != 1 {
		t.Errorf("summary %+v, want 1 manual suspension pending review", page.Summary)
	}
	if visitor, ok := listed(page, guest.ID); !ok || visitor.CanManage || visitor.Reason != "managed_elsewhere" || visitor.Source != "external" || visitor.Risk != "unknown" || visitor.SuspendedAt != nil {
		t.Errorf("another organisation's suspension is listed as %+v (listed %t), want it without its reason, risk or time", visitor, ok)
	}
	if _, ok := listed(suspendedPage(t, as, "?source=policy"), target.ID); ok {
		t.Error("filtering by policy source lists a manual suspension")
	}
	if _, ok := listed(suspendedPage(t, as, "?q="+strings.Split(target.Email, "@")[0]), target.ID); !ok {
		t.Error("searching by the person's email doesn't find their suspension")
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users/suspended?reason=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("filter by an unknown reason: %d, want 400", rec.Code)
	}

	review := map[string]any{"reason": "account_compromise", "risk": "high", "review": "reviewed"}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", review); rec.Code != http.StatusNoContent {
		t.Fatalf("review the suspension: %d %s", rec.Code, rec.Body.String())
	}
	if got, ok := listed(suspendedPage(t, as, "?risk=high&review=reviewed"), target.ID); !ok || got.Reason != "account_compromise" {
		t.Errorf("the reviewed suspension is listed as %+v (listed %t)", got, ok)
	}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", map[string]any{"reason": "bored", "risk": "high", "review": "reviewed"}); rec.Code != http.StatusBadRequest {
		t.Errorf("review with an unknown reason: %d, want 400", rec.Code)
	}

	asTarget := dbtest.Serve(dbtest.Principal(target.ID, tenant), h.Mount)
	if rec := dbtest.Do(t, asTarget, http.MethodPatch, path, map[string]any{"status": "active"}); rec.Code != http.StatusForbidden {
		t.Errorf("the person lifting their own suspension: %d, want 403", rec.Code)
	}
	if rec := dbtest.Do(t, asTarget, http.MethodPost, path+"/reactivate", nil); rec.Code != http.StatusForbidden {
		t.Errorf("the person reactivating themselves: %d, want 403", rec.Code)
	}

	rec := dbtest.Do(t, as, http.MethodPost, path+"/reactivate", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("reactivate: %d %s", rec.Code, rec.Body.String())
	}
	if n := audited(t, tenant, "user.reactivated", target.ID); n != 1 {
		t.Errorf("%d user.reactivated audit events, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE id = $1 AND suspended_at IS NULL AND suspension_reason IS NULL`, target.ID); n != 1 {
		t.Error("reactivating kept the suspension's details")
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/reactivate", nil); rec.Code != http.StatusConflict {
		t.Errorf("reactivate an active account: %d, want 409", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodPut, path+"/suspension", review); rec.Code != http.StatusConflict {
		t.Errorf("review the suspension of an active account: %d, want 409", rec.Code)
	}
}

// TestDeleteRestoreAndPurge checks the recycle bin: a deletion records who did
// it and ends the person's sessions, restoring brings back the account but no
// session, a purge removes only a deleted account, and another organisation
// can do none of it.
func TestDeleteRestoreAndPurge(t *testing.T) {
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	otherAdmin := dbtest.User(t, other, other)
	target := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, target.ID, "Kx7mQ2vLp9Wz")
	session(t, target.ID, tenant, "")
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	asOther := dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), h.Mount)
	path := "/users/" + target.ID.String()

	rec := dbtest.Do(t, as, http.MethodDelete, path, nil)
	var d Deletion
	dbtest.Decode(t, rec, &d)
	if rec.Code != http.StatusOK || d.ID != target.ID || d.DeletedBy == nil || *d.DeletedBy != admin.ID || d.DeletedAt.IsZero() {
		t.Fatalf("delete: %d %+v, want the deletion recorded as the administrator's", rec.Code, d)
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("%d sessions are still live after the deletion", n)
	}
	if n := audited(t, tenant, "user.deleted", target.ID); n != 1 {
		t.Errorf("%d user.deleted audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("read a deleted user: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete twice: %d, want 404", rec.Code)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, as, http.MethodGet, "/users/deleted", nil)); !slices.Contains(ids, target.ID) {
		t.Error("the recycle bin leaves out the deleted user")
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asOther, http.MethodGet, "/users/deleted", nil)); slices.Contains(ids, target.ID) {
		t.Error("another organisation's recycle bin shows the deleted user")
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, path + "/restore"},
		{http.MethodDelete, path + "/purge"},
	} {
		if rec := dbtest.Do(t, asOther, tc.method, tc.path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s %s: %d, want 404", tc.method, tc.path, rec.Code)
		}
	}

	rec = dbtest.Do(t, as, http.MethodPost, path+"/restore", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body.String())
	}
	if n := liveSessions(t, target.ID); n != 0 {
		t.Errorf("restoring the account brought back %d sessions", n)
	}
	if n := audited(t, tenant, "user.restored", target.ID); n != 1 {
		t.Errorf("%d user.restored audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/restore", nil); rec.Code != http.StatusNotFound {
		t.Errorf("restore a live account: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path+"/purge", nil); rec.Code != http.StatusNotFound {
		t.Errorf("purge a live account: %d, want 404", rec.Code)
	}

	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete again: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path+"/purge", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("purge: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT (SELECT count(*) FROM "user".users WHERE id = $1) + (SELECT count(*) FROM auth.password_credentials WHERE user_id = $1)`, target.ID); n != 0 {
		t.Error("the purge left the account or its password behind")
	}
	if n := audited(t, tenant, "user.purged", target.ID); n != 1 {
		t.Errorf("%d user.purged audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodPost, path+"/restore", nil); rec.Code != http.StatusNotFound {
		t.Errorf("restore a purged account: %d, want 404", rec.Code)
	}
}

// TestRestoreWithATakenEmail checks that restoring an account whose email a
// newer account has taken meanwhile is refused as a conflict.
func TestRestoreWithATakenEmail(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	target := dbtest.User(t, tenant, tenant)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), testHandler(t, nil).Mount)
	if rec := dbtest.Do(t, as, http.MethodDelete, "/users/"+target.ID.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as, http.MethodPost, "/users", map[string]any{"email": target.Email}); rec.Code != http.StatusCreated {
		t.Fatalf("create a new account with the deleted one's email: %d %s", rec.Code, rec.Body.String())
	}
	rec := dbtest.Do(t, as, http.MethodPost, "/users/"+target.ID.String()+"/restore", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeAuthEmailExists) {
		t.Errorf("restore an account whose email is taken: %d %s, want 409 %s", rec.Code, rec.Body.String(), errs.CodeAuthEmailExists)
	}
}

// TestRemovingAMemberLeavesTheirHomeAlone checks that an organisation removing
// a member from elsewhere takes away their roles, groups, sessions, grants and
// API keys there and nothing in their home organisation, which can't remove
// them this way.
func TestRemovingAMemberLeavesTheirHomeAlone(t *testing.T) {
	home, tenant := dbtest.Tenant(t), dbtest.Tenant(t)
	homeAdmin := dbtest.User(t, home, home)
	admin := dbtest.User(t, tenant, tenant)
	member := dbtest.User(t, home, home, tenant)
	for _, in := range []uuid.UUID{home, tenant} {
		session(t, member.ID, in, "")
		exec(t, `
			WITH g AS (INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id)
			INSERT INTO tenant.group_members (group_id, user_id, tenant_id) SELECT id, $3, $1 FROM g
		`, in, dbtest.Unique("group"), member.ID)
		exec(t, `INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at)
			VALUES (gen_random_uuid()::text, 'test-app', $1, $2, NOW() + INTERVAL '1 day')`, member.ID, in)
		exec(t, `INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash) VALUES ($1, $2, 'key', 'prefix00', 'hash')`, in, member.ID)
	}
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	path := "/users/" + member.ID.String() + "/membership"

	rec := dbtest.Do(t, as, http.MethodDelete, path, nil)
	var removal Removal
	dbtest.Decode(t, rec, &removal)
	if rec.Code != http.StatusOK || removal != (Removal{ID: member.ID, RolesRemoved: 1, SessionsEnded: 1}) {
		t.Fatalf("remove the member: %d %+v, want 1 role and 1 session", rec.Code, removal)
	}
	for _, left := range []struct{ what, sql string }{
		{"roles", `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`},
		{"groups", `SELECT count(*) FROM tenant.group_members WHERE user_id = $1 AND tenant_id = $2`},
		{"sessions", `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`},
		{"application grants", `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`},
		{"API keys", `SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`},
	} {
		if n := dbtest.Count(t, left.sql, member.ID, tenant); n != 0 {
			t.Errorf("%d %s are left in the organisation the member was removed from", n, left.what)
		}
		if n := dbtest.Count(t, left.sql, member.ID, home); n != 1 {
			t.Errorf("removing the member elsewhere left %d %s in their home organisation, want 1", n, left.what)
		}
	}
	if n := audited(t, tenant, "user.removed_from_organization", member.ID); n != 1 {
		t.Errorf("%d user.removed_from_organization audit events, want 1", n)
	}
	if rec := dbtest.Do(t, as, http.MethodGet, "/users/"+member.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("read a removed member: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, as, http.MethodDelete, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("remove the member twice: %d, want 404", rec.Code)
	}

	asHome := dbtest.Serve(dbtest.Principal(homeAdmin.ID, home), h.Mount)
	if rec := dbtest.Do(t, asHome, http.MethodDelete, path, nil); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errs.CodeUserManagedHere) {
		t.Errorf("the home organisation removing its own account: %d %s, want 409 %s", rec.Code, rec.Body.String(), errs.CodeUserManagedHere)
	}
}

// TestMemberFromElsewhereIsReadOnly checks that an organisation can read a
// member whose account another organisation manages, but can't change, suspend,
// delete or sign them out, set their password or touch their second factors.
func TestMemberFromElsewhereIsReadOnly(t *testing.T) {
	home, tenant := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	member := dbtest.User(t, home, home, tenant)
	session(t, member.ID, home, "")
	h := testHandler(t, nil)
	as := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	path := "/users/" + member.ID.String()

	for _, read := range []string{path, path + "/security", path + "/sessions", path + "/access"} {
		if rec := dbtest.Do(t, as, http.MethodGet, read, nil); rec.Code != http.StatusOK {
			t.Errorf("read %s of a member from elsewhere: %d, want 200", read, rec.Code)
		}
	}
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPatch, path, map[string]any{"display_name": "changed"}},
		{http.MethodPatch, path, map[string]any{"status": "suspended"}},
		{http.MethodPost, path + "/reactivate", nil},
		{http.MethodPut, path + "/suspension", map[string]any{"reason": "other", "risk": "low", "review": "reviewed"}},
		{http.MethodDelete, path, nil},
		{http.MethodPost, path + "/restore", nil},
		{http.MethodDelete, path + "/purge", nil},
		{http.MethodPost, path + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-other"}},
		{http.MethodDelete, path + "/mfa", nil},
		{http.MethodPost, path + "/sessions/revoke-all", nil},
		{http.MethodPut, path + "/mfa-required", map[string]any{"required": true}},
	} {
		rec := dbtest.Do(t, as, tc.method, tc.path, tc.body)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeUserManagedElsewhere) {
			t.Errorf("another organisation %s %s: %d %s, want 403 %s", tc.method, tc.path, rec.Code, rec.Body.String(), errs.CodeUserManagedElsewhere)
		}
	}
	if n := dbtest.Count(t, `
		SELECT count(*) FROM "user".users
		WHERE id = $1 AND status = 'active' AND deleted_at IS NULL AND display_name IS NULL AND NOT mfa_required
	`, member.ID); n != 1 {
		t.Error("another organisation changed the member's account")
	}
	if n := liveSessions(t, member.ID); n != 1 {
		t.Errorf("another organisation's refused actions left %d live sessions, want 1", n)
	}
}
