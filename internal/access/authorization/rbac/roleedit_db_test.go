//go:build integration

package rbac

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestCustomRolesAreEditedWhole checks that a custom role's permissions are
// set in one change (all or nothing, held to what the caller may give, one
// audit record, none for no change), that it is renamed under a name no other
// role has, and that it is deleted only once nobody, no group and no open
// invitation holds it; and that a built-in role takes none of these.
func TestCustomRolesAreEditedWhole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, editor := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "role.read", "role.write", "user.read"))
	support := dbtest.Role(t, organization, "user.read", "audit.read")
	foreign := dbtest.Role(t, other, "user.read")
	perm := map[string]string{}
	for _, key := range []string{"user.read", "audit.read", "role.read"} {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, key).Scan(&id); err != nil {
			t.Fatal(err)
		}
		perm[key] = id.String()
	}

	h := &Handler{Repo: repo, Service: NewService(repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, organization), h.Mount)
	asEditor := dbtest.Serve(dbtest.Principal(editor.ID, organization), h.Mount)
	rolePath := func(role uuid.UUID) string {
		return "/organizations/" + organization.String() + "/roles/" + role.String()
	}
	check := func(name string, status int, code string, method string, as http.Handler, path string, body any) []byte {
		t.Helper()
		rec := dbtest.Do(t, as, method, path, body)
		if rec.Code != status || !strings.Contains(rec.Body.String(), code) {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), status, code)
		}
		return rec.Body.Bytes()
	}
	audited := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = $2 AND resource_id = $3`, organization, action, support)
	}

	set := map[string]any{"permission_ids": []string{perm["user.read"], perm["role.read"]}}
	check("an editor takes away audit.read, which they lack", http.StatusForbidden, errs.CodeRBACGrantExceedsCaller, http.MethodPut, asEditor, rolePath(support)+"/permissions", set)
	if got := permissionKeys(t, support); len(got) != 2 || !slices.Contains(got, "audit.read") {
		t.Errorf("a refused change left %v, want user.read and audit.read", got)
	}
	var page struct {
		Items []Permission `json:"items"`
	}
	if err := json.Unmarshal(check("the owner sets the role's permissions", http.StatusOK, "", http.MethodPut, asOwner, rolePath(support)+"/permissions", set), &page); err != nil {
		t.Fatal(err)
	}
	if got := permissionKeys(t, support); !slices.Equal(slices.Sorted(slices.Values(got)), []string{"role.read", "user.read"}) || len(page.Items) != 2 {
		t.Errorf("after setting: %v, answered %v; want role.read and user.read", got, page.Items)
	}
	var change struct{ Added, Removed []string }
	if err := pool.QueryRow(ctx, `SELECT metadata->'added', metadata->'removed' FROM audit.events WHERE organization_id = $1 AND action = 'role.permissions_set' AND resource_id = $2`, organization, support).Scan(&change.Added, &change.Removed); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(change.Added, []string{"role.read"}) || !slices.Equal(change.Removed, []string{"audit.read"}) {
		t.Errorf("audited added %v removed %v, want [role.read] [audit.read]", change.Added, change.Removed)
	}
	check("setting the same again", http.StatusOK, "", http.MethodPut, asOwner, rolePath(support)+"/permissions", set)
	if n := audited("role.permissions_set"); n != 1 {
		t.Errorf("%d role.permissions_set records, want the one change only", n)
	}
	check("an unknown permission", http.StatusNotFound, errs.CodeNotFound, http.MethodPut, asOwner, rolePath(support)+"/permissions", map[string]any{"permission_ids": []string{uuid.NewString()}})
	check("no permission_ids", http.StatusBadRequest, "", http.MethodPut, asOwner, rolePath(support)+"/permissions", map[string]any{})
	check("another organization's role", http.StatusNotFound, errs.CodeNotFound, http.MethodPut, asOwner, rolePath(foreign)+"/permissions", set)
	check("the owner role", http.StatusForbidden, CodeSystemRoleFixed, http.MethodPut, asOwner, rolePath(ownerRole)+"/permissions", set)

	check("renaming it", http.StatusOK, `"name":"Helpdesk"`, http.MethodPatch, asEditor, rolePath(support), map[string]any{"name": "Helpdesk"})
	check("renaming it after another role", http.StatusConflict, CodeRoleNameExists, http.MethodPatch, asEditor, rolePath(support), map[string]any{"name": "OWNER"})
	check("renaming the owner role", http.StatusForbidden, CodeSystemRoleFixed, http.MethodPatch, asOwner, rolePath(ownerRole), map[string]any{"name": "boss"})
	check("renaming another organization's role", http.StatusNotFound, errs.CodeNotFound, http.MethodPatch, asOwner, rolePath(foreign), map[string]any{"name": "x"})
	if n := audited("role.updated"); n != 1 {
		t.Errorf("%d role.updated records, want 1", n)
	}

	holder := dbtest.User(t, organization)
	dbtest.Assign(t, holder.ID, organization, support)
	check("deleting a role someone holds", http.StatusConflict, errs.CodeRBACRoleInUse, http.MethodDelete, asOwner, rolePath(support), nil)
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2 AND role_id = $3`, holder.ID, organization, support); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.invites (organization_id, email, role_id, token_hash, expires_at) VALUES ($1, $2, $3, $4, now() + interval '1 day')`,
		organization, dbtest.Unique("i")+"@example.com", support, dbtest.Unique("h")); err != nil {
		t.Fatal(err)
	}
	if body := check("deleting a role an invitation offers", http.StatusConflict, errs.CodeRBACRoleInUse, http.MethodDelete, asOwner, rolePath(support), nil); !strings.Contains(string(body), `"invitations":1`) {
		t.Errorf("the refusal doesn't count the invitation: %s", body)
	}
	if _, err := pool.Exec(ctx, `UPDATE organization.invites SET status = 'revoked' WHERE organization_id = $1 AND role_id = $2`, organization, support); err != nil {
		t.Fatal(err)
	}
	check("deleting the owner role", http.StatusForbidden, CodeSystemRoleFixed, http.MethodDelete, asOwner, rolePath(ownerRole), nil)
	check("deleting it once nobody holds it", http.StatusNoContent, "", http.MethodDelete, asEditor, rolePath(support), nil)
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.roles WHERE id = $1`, support); n != 0 || audited("role.deleted") != 1 {
		t.Errorf("after deleting: %d roles, %d role.deleted records; want 0 and 1", n, audited("role.deleted"))
	}
}

// TestEffectivePermissionsSayWhereEachComesFrom checks that a person's
// effective permissions come with every grant behind them: the role, held
// directly or through which group, one entry for each.
func TestEffectivePermissionsSayWhereEachComesFrom(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	person, admin := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "role.read"))
	readers := dbtest.Role(t, organization, "user.read")
	dbtest.Assign(t, person.ID, organization, readers)
	auditors := dbtest.Role(t, organization, "user.read", "audit.read")
	var group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Frontend') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, group, auditors); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, organization, group, person.ID); err != nil {
		t.Fatal(err)
	}

	h := &Handler{Repo: repo, Service: NewService(repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount), http.MethodGet, "/users/"+person.ID.String()+"/organizations/"+organization.String()+"/permissions", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Permissions []string    `json:"permissions"`
		Grants      []GrantStep `json:"grants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	type grant struct{ permission, via, group string }
	var grants []grant
	for _, g := range got.Grants {
		if g.Via == "direct" && (g.RoleID != readers || g.GroupID != nil) || g.Via != "direct" && (g.RoleID != auditors || g.GroupID == nil || *g.GroupID != group) {
			t.Errorf("a grant names the wrong role or group: %+v", g)
		}
		grants = append(grants, grant{g.Permission, g.Via, g.GroupName})
	}
	want := []grant{{"audit.read", "group:Frontend", "Frontend"}, {"user.read", "direct", ""}, {"user.read", "group:Frontend", "Frontend"}}
	if !slices.Equal(grants, want) || len(got.Permissions) != 2 {
		t.Errorf("permissions %v with grants %v, want two with %v", got.Permissions, grants, want)
	}
}
