//go:build integration

package user

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestAdminsChangeOnlyPeopleTheyOutrank checks that changing an account (its
// password, second factors, status, existence) needs the caller to hold every
// permission the person holds, and only an owner changes an owner, so a
// helpdesk admin can reset a colleague but not take over an owner or an admin.
func TestAdminsChangeOnlyPeopleTheyOutrank(t *testing.T) {
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	person := func(perms ...string) uuid.UUID {
		t.Helper()
		u := dbtest.User(t, tenant)
		dbtest.Assign(t, u.ID, tenant, dbtest.Role(t, tenant, perms...))
		return u.ID
	}
	owner := dbtest.User(t, tenant).ID
	var ownerRole uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, owner, tenant, ownerRole)
	helpdesk := person("user.read", "user.write")
	admin := person("user.read", "user.write", "role.write")
	colleague := person("user.read")

	h := testHandler(t, &dbtest.Mailbox{})
	as := func(caller uuid.UUID) http.Handler { return dbtest.Serve(dbtest.Principal(caller, tenant), h.Mount) }
	type call struct {
		method, path string
		body         any
	}
	changes := func(id uuid.UUID) []call {
		p := "/users/" + id.String()
		return []call{
			{http.MethodPost, p + "/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}},
			{http.MethodDelete, p + "/mfa", nil},
			{http.MethodPost, p + "/sessions/revoke-all", nil},
			{http.MethodPut, p + "/mfa-required", map[string]any{"required": true}},
			{http.MethodPatch, p, map[string]any{"status": "suspended"}},
			{http.MethodDelete, p, nil},
		}
	}
	for target, code := range map[uuid.UUID]string{owner: errs.CodeRBACTargetIsOwner, admin: errs.CodeRBACTargetOutranks} {
		for _, c := range changes(target) {
			rec := dbtest.Do(t, as(helpdesk), c.method, c.path, c.body)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), code) {
				t.Errorf("helpdesk %s %s: %d %s, want 403 %s", c.method, c.path, rec.Code, rec.Body.String(), code)
			}
		}
	}
	if rec := dbtest.Do(t, as(helpdesk), http.MethodPost, "/users/"+colleague.String()+"/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}); rec.Code != http.StatusNoContent {
		t.Errorf("helpdesk resets a colleague's password: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, as(owner), http.MethodPost, "/users/"+admin.String()+"/password", map[string]any{"password": "Kx7mQ2vLp9Wz-new"}); rec.Code != http.StatusNoContent {
		t.Errorf("an owner resets an admin's password: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = ANY($1) AND tenant_id = $2 AND status = 'active' AND deleted_at IS NULL`,
		[]uuid.UUID{owner, admin}, tenant); n != 2 {
		t.Errorf("%d of the owner and admin still active, want both", n)
	}
}
