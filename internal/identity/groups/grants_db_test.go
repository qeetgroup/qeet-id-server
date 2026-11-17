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
	organization := dbtest.Organization(t)
	editor := dbtest.User(t, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "group.write", "user.read"))
	group := func(name string, roles ...uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, role := range roles {
			if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, id, role); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owners := group("Owners", ownerRole)
	admins := group("Administrators", dbtest.Role(t, organization, "role.write", "user.write"))
	team := group("Payments team")

	h := dbtest.Serve(dbtest.Principal(editor.ID, organization),
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
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE organization_id = $1 AND user_id = $2`, organization, editor.ID); n != 1 {
		t.Errorf("the editor is in %d groups, want only the one without roles", n)
	}
}

// TestRemovingFromAGroupIsHeldToTheGrantRule checks that taking someone out of
// a group, or deleting it, takes its roles away, so it needs what they carry,
// as giving them does: a group editor removes no owner from the owners' group,
// no one from a group whose roles they lack, and no one who outranks them,
// nor deletes such a group; a group whose roles they hold is theirs to change.
func TestRemovingFromAGroupIsHeldToTheGrantRule(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	editor := dbtest.User(t, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "group.write", "user.read"))
	group := func(name string, roles ...uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, $2) RETURNING id`, organization, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		for _, role := range roles {
			if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, id, role); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	member := func(g uuid.UUID) dbtest.Account {
		t.Helper()
		a := dbtest.User(t, organization, organization)
		if _, err := pool.Exec(ctx, `INSERT INTO organization.group_members (organization_id, group_id, user_id) VALUES ($1, $2, $3)`, organization, g, a.ID); err != nil {
			t.Fatal(err)
		}
		return a
	}
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owners := group("Owners", ownerRole)
	admins := group("Administrators", dbtest.Role(t, organization, "role.write", "user.write"))
	team, readers := group("Payments team"), group("Readers", dbtest.Role(t, organization, "user.read"))
	owner, admin := member(owners), member(admins)
	senior, plain := member(team), member(team)
	dbtest.Assign(t, senior.ID, organization, dbtest.Role(t, organization, "role.write"))
	member(readers)

	repo := rbac.NewRepository(pool)
	h := dbtest.Serve(dbtest.Principal(editor.ID, organization),
		(&Handler{Service: NewService(pool), GrantCheck: repo.CheckGrantGroup, ActOnCheck: repo.CheckActOn}).Mount)
	call := func(method, path string) (int, string) {
		rec := dbtest.Do(t, h, method, path, nil)
		return rec.Code, rec.Body.String()
	}
	remove := func(g uuid.UUID, a dbtest.Account) (int, string) {
		return call(http.MethodDelete, "/groups/"+g.String()+"/members/"+a.ID.String())
	}
	for _, c := range []struct {
		name   string
		status int
		code   string
		do     func() (int, string)
	}{
		{"remove an owner from the owners' group", http.StatusForbidden, errs.CodeRBACOwnerOnly, func() (int, string) { return remove(owners, owner) }},
		{"remove someone from a group with role.write", http.StatusForbidden, errs.CodeRBACGrantExceedsCaller, func() (int, string) { return remove(admins, admin) }},
		{"remove someone who outranks them from a group with no roles", http.StatusForbidden, errs.CodeRBACTargetOutranks, func() (int, string) { return remove(team, senior) }},
		{"delete the owners' group", http.StatusForbidden, errs.CodeRBACOwnerOnly, func() (int, string) { return call(http.MethodDelete, "/groups/"+owners.String()) }},
		{"delete a group with role.write", http.StatusForbidden, errs.CodeRBACGrantExceedsCaller, func() (int, string) { return call(http.MethodDelete, "/groups/"+admins.String()) }},
		{"remove someone from a group with no roles", http.StatusNoContent, "", func() (int, string) { return remove(team, plain) }},
		{"delete a group whose roles they hold", http.StatusNoContent, "", func() (int, string) { return call(http.MethodDelete, "/groups/"+readers.String()) }},
	} {
		if status, body := c.do(); status != c.status || !strings.Contains(body, c.code) {
			t.Errorf("a group editor tries to %s: %d %s, want %d %s", c.name, status, body, c.status, c.code)
		}
	}
	for _, a := range []dbtest.Account{owner, admin, senior} {
		if n := dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE organization_id = $1 AND user_id = $2`, organization, a.ID); n != 1 {
			t.Errorf("%s left their group, want them kept", a.Email)
		}
	}
}
