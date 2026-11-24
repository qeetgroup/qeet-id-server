//go:build integration

package rbac

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestCredentialsCarryNoMoreThanTheirIssuer checks that a person issues a
// machine credential only with scopes their permissions cover (vault scopes
// needing secret.read), an owner any, and that a credential issues or grants
// only within its own scopes, no more than the person it acts for holds now,
// and never the owner role.
func TestCredentialsCarryNoMoreThanTheirIssuer(t *testing.T) {
	ctx := dbtest.Context(t)
	repo := NewRepository(dbtest.Pool(t))
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	devRole := dbtest.Role(t, organization, "apikey.write", "user.read")
	dbtest.Assign(t, developer.ID, organization, devRole)
	owner := dbtest.User(t, organization)
	var ownerRole uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, owner.ID, organization, ownerRole)

	refused := func(err error, permission string) bool {
		e := errs.As(err)
		return errors.Is(err, errs.ErrRBACGrantExceedsCaller) && e != nil && e.Metadata["permission"] == permission
	}
	asDeveloper := dbtest.Principal(developer.ID, organization)
	if err := repo.CheckGrantScopes(ctx, asDeveloper, organization, []string{"user.read", "apikey.write"}); err != nil {
		t.Errorf("a developer issues their own permissions: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, asDeveloper, organization, []string{"user.read", "role.write"}); !refused(err, "role.write") {
		t.Errorf("a developer issues role.write: %v, want %v naming it", err, errs.ErrRBACGrantExceedsCaller)
	}
	if err := repo.CheckGrantScopes(ctx, asDeveloper, organization, []string{"vault:read"}); !refused(err, "vault:read") {
		t.Errorf("a developer without secret.read issues vault:read: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, dbtest.Principal(owner.ID, organization), organization, []string{"role.write", "organization.write", "vault:read"}); err != nil {
		t.Errorf("an owner issues anything: %v", err)
	}

	// The owner's own key, narrowly scoped, holds only its scopes.
	ownersKey := &httpx.Principal{UserID: &owner.ID, OrganizationID: &organization, ActorType: "api_key", Scopes: []string{"apikey.write", "role.write", "vault:payments"}}
	if err := repo.CheckGrantScopes(ctx, ownersKey, organization, []string{"role.write", "vault:payments"}); err != nil {
		t.Errorf("a key issues its own scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, ownersKey, organization, []string{"user.write"}); !refused(err, "user.write") {
		t.Errorf("an owner's key issues beyond its scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, ownersKey, organization, []string{"vault:read"}); !refused(err, "vault:read") {
		t.Errorf("a key holding one vault secret issues all of them: %v", err)
	}
	if err := repo.CheckGrantRole(ctx, ownersKey, organization, ownerRole); !errors.Is(err, errs.ErrRBACOwnerOnly) {
		t.Errorf("an owner's key gives the owner role: %v, want %v", err, errs.ErrRBACOwnerOnly)
	}

	// A key outlives a demotion only within what its person still holds.
	developersKey := &httpx.Principal{UserID: &developer.ID, OrganizationID: &organization, ActorType: "api_key", Scopes: []string{"apikey.write", "user.read", "role.write"}}
	if err := repo.CheckGrantScopes(ctx, developersKey, organization, []string{"role.write"}); !refused(err, "role.write") {
		t.Errorf("a key issues a scope its person no longer holds: %v", err)
	}
	service := &httpx.Principal{OrganizationID: &organization, ActorType: "service", Scopes: []string{"apikey.write", "vault:read"}}
	if err := repo.CheckGrantScopes(ctx, service, organization, []string{"vault:payments", "apikey.write"}); err != nil {
		t.Errorf("a service principal issues within its scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, service, organization, []string{"secret.read"}); !refused(err, "secret.read") {
		t.Errorf("a service principal issues a permission it lacks: %v", err)
	}
}

// TestOwnersAndTheOwnerRoleStayProtected checks that the built-in owner role's
// permissions can't be changed, that nobody takes away a permission they don't
// hold, and that only an owner removes someone's owner role or strips an
// owner of other roles.
func TestOwnersAndTheOwnerRoleStayProtected(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, coOwner := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, coOwner.ID, organization, ownerRole)
	reviewers := dbtest.Role(t, organization, "audit.read")
	dbtest.Assign(t, coOwner.ID, organization, reviewers)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "role.read", "role.write", "user.read"))
	var auditRead, roleWrite uuid.UUID
	for key, id := range map[string]*uuid.UUID{"audit.read": &auditRead, "role.write": &roleWrite} {
		if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, key).Scan(id); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	as := func(u uuid.UUID) http.Handler { return dbtest.Serve(dbtest.Principal(u, organization), h.Mount) }
	for _, tc := range []struct {
		name         string
		caller       uuid.UUID
		method, path string
		status       int
		code         string
	}{
		{"an owner revokes from the owner role", owner.ID, http.MethodDelete, "/roles/" + ownerRole.String() + "/permissions/" + roleWrite.String(), http.StatusForbidden, CodeSystemRoleFixed},
		{"an admin grants to the owner role", admin.ID, http.MethodPost, "/roles/" + ownerRole.String() + "/permissions/" + roleWrite.String(), http.StatusForbidden, CodeSystemRoleFixed},
		{"an admin revokes a permission they lack", admin.ID, http.MethodDelete, "/roles/" + reviewers.String() + "/permissions/" + auditRead.String(), http.StatusForbidden, errs.CodeRBACGrantExceedsCaller},
		{"an admin removes an owner's owner role", admin.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/organizations/" + organization.String() + "/roles/" + ownerRole.String(), http.StatusForbidden, errs.CodeRBACTargetIsOwner},
		{"an admin strips an owner of another role", admin.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/organizations/" + organization.String() + "/roles/" + reviewers.String(), http.StatusForbidden, errs.CodeRBACTargetIsOwner},
		{"an owner removes a co-owner's owner role", owner.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/organizations/" + organization.String() + "/roles/" + ownerRole.String(), http.StatusNoContent, ""},
	} {
		rec := dbtest.Do(t, as(tc.caller), tc.method, tc.path, nil)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.role_permissions WHERE role_id = $1`, reviewers); n != 1 {
		t.Errorf("the reviewers' role has %d permissions, want its one kept", n)
	}
}

// TestBuiltinRolesHoldTheirDefinitions checks that seeding at boot gives an
// organization's built-in roles what their definitions cover of the catalogue
// (owner everything, admin all but organization.delete, viewer every read but
// secret.read, member nothing), that nobody changes them, and that none counts
// as a custom role.
func TestBuiltinRolesHoldTheirDefinitions(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	roles := map[string]uuid.UUID{}
	for _, name := range []string{"owner", "admin", "member", "viewer"} {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, $2, true) RETURNING id`, organization, name).Scan(&id); err != nil {
			t.Fatal(err)
		}
		roles[name] = id
	}
	if err := repo.SeedBuiltins(ctx); err != nil {
		t.Fatal(err)
	}
	for name, role := range roles {
		held := map[string]bool{}
		for _, key := range permissionKeys(t, role) {
			held[key] = true
		}
		for _, p := range builtinPermissionDefinitions {
			want := map[string]bool{
				"owner":  true,
				"admin":  p.Key != "organization.delete",
				"member": false,
				"viewer": strings.HasSuffix(p.Key, ".read") && p.Key != "secret.read",
			}[name]
			if held[p.Key] != want {
				t.Errorf("the built-in %s role holds %s: %v, want %v", name, p.Key, held[p.Key], want)
			}
		}
	}
	if n, err := repo.CountCustomRoles(ctx, organization); err != nil || n != 0 {
		t.Errorf("custom roles: %d, %v; want the built-in ones not counted", n, err)
	}

	owner := dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, roles["owner"])
	var organizationDelete, auditRead uuid.UUID
	for key, id := range map[string]*uuid.UUID{"organization.delete": &organizationDelete, "audit.read": &auditRead} {
		if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, key).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	asOwner := dbtest.Serve(dbtest.Principal(owner.ID, organization), h.Mount)
	for _, tc := range []struct{ name, method, path string }{
		{"an owner grants organization.delete to admin", http.MethodPost, "/roles/" + roles["admin"].String() + "/permissions/" + organizationDelete.String()},
		{"an owner takes audit.read from viewer", http.MethodDelete, "/roles/" + roles["viewer"].String() + "/permissions/" + auditRead.String()},
		{"an owner grants audit.read to member", http.MethodPost, "/roles/" + roles["member"].String() + "/permissions/" + auditRead.String()},
	} {
		rec := dbtest.Do(t, asOwner, tc.method, tc.path, nil)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeSystemRoleFixed) {
			t.Errorf("%s: %d %s, want 403 %s", tc.name, rec.Code, rec.Body.String(), CodeSystemRoleFixed)
		}
	}
}

// permissionKeys lists the permissions role holds.
func permissionKeys(t *testing.T, role uuid.UUID) []string {
	t.Helper()
	var keys []string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT coalesce(array_agg(p.key), '{}') FROM rbac.role_permissions rp
		JOIN rbac.permissions p ON p.id = rp.permission_id WHERE rp.role_id = $1`, role).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	return keys
}

// TestRemovingARoleFromAGroupNeedsTheRole checks that taking a role off a group
// is held to the rule for giving it, as taking it off a person is: only an
// owner takes the owner role off a group, and a role editor takes off no role
// carrying a permission they lack.
func TestRemovingARoleFromAGroupNeedsTheRole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	editor := dbtest.User(t, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "role.write", "group.read"))
	var ownerRole, group uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Owners') RETURNING id`, organization).Scan(&group); err != nil {
		t.Fatal(err)
	}
	powerful, held := dbtest.Role(t, organization, "user.write"), dbtest.Role(t, organization, "group.read")
	for _, role := range []uuid.UUID{ownerRole, powerful, held} {
		if _, err := pool.Exec(ctx, `INSERT INTO rbac.group_roles (organization_id, group_id, role_id) VALUES ($1, $2, $3)`, organization, group, role); err != nil {
			t.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(editor.ID, organization),
		(&Handler{Repo: repo, Service: newRoleService(t, repo), Validate: validator.New(validator.WithRequiredStructEnabled())}).Mount)
	unassign := func(role uuid.UUID) (int, string) {
		rec := dbtest.Do(t, h, http.MethodDelete, "/organizations/"+organization.String()+"/groups/"+group.String()+"/roles/"+role.String(), nil)
		return rec.Code, rec.Body.String()
	}

	if status, body := unassign(ownerRole); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACOwnerOnly) {
		t.Errorf("a role editor takes the owner role off a group: %d %s, want 403 %s", status, body, errs.CodeRBACOwnerOnly)
	}
	if status, body := unassign(powerful); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACGrantExceedsCaller) {
		t.Errorf("a role editor takes off a role with user.write: %d %s, want 403 %s", status, body, errs.CodeRBACGrantExceedsCaller)
	}
	if status, body := unassign(held); status != http.StatusNoContent {
		t.Errorf("a role editor takes off a role they hold: %d %s, want 204", status, body)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.group_roles WHERE organization_id = $1 AND group_id = $2`, organization, group); n != 2 {
		t.Errorf("the group holds %d roles, want the 2 the editor couldn't take off", n)
	}
}
