//go:build integration

package group

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestGroupMembershipNeedsTheGroupsAuthority checks that adding someone to a
// group gives the group's roles, so it needs what they carry: only an owner adds
// to a group holding the owner role, and a group editor can't add themselves to
// a group whose roles they lack.
func TestGroupMembershipNeedsTheGroupsAuthority(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	editor := dbtest.User(t, tenant)
	dbtest.Assign(t, editor.ID, tenant, dbtest.Role(t, tenant, "group.write", "user.read"))
	group := func(name string, roles ...uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenant, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, role := range roles {
			if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, tenant, id, role); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owners := group("Owners", ownerRole)
	admins := group("Administrators", dbtest.Role(t, tenant, "role.write", "user.write"))
	team := group("Payments team")

	h := dbtest.Serve(dbtest.Principal(editor.ID, tenant),
		(&Handler{Service: NewService(pool), GrantCheck: rbac.NewRepository(pool).CheckGrantGroup}).Mount)
	add := func(g uuid.UUID) (int, string) {
		rec := dbtest.Do(t, h, http.MethodPost, "/groups/"+g.String()+"/members/"+editor.ID.String(), nil)
		return rec.Code, rec.Body.String()
	}
	if code, body := add(owners); code != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACOwnerOnly) {
		t.Errorf("a group editor joins the owners' group: %d %s, want 403 %s", code, body, errs.CodeRBACOwnerOnly)
	}
	if code, body := add(admins); code != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACGrantExceedsCaller) {
		t.Errorf("a group editor joins a group with role.write: %d %s, want 403 %s", code, body, errs.CodeRBACGrantExceedsCaller)
	}
	if code, body := add(team); code != http.StatusNoContent {
		t.Errorf("a group editor joins a group with no roles: %d %s, want 204", code, body)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.group_members WHERE tenant_id = $1 AND user_id = $2`, tenant, editor.ID); n != 1 {
		t.Errorf("the editor is in %d groups, want only the one without roles", n)
	}
}
