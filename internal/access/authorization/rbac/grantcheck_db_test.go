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
	tenant := dbtest.Tenant(t)
	developer := dbtest.User(t, tenant)
	devRole := dbtest.Role(t, tenant, "apikey.write", "user.read")
	dbtest.Assign(t, developer.ID, tenant, devRole)
	owner := dbtest.User(t, tenant)
	var ownerRole uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, owner.ID, tenant, ownerRole)

	refused := func(err error, permission string) bool {
		e := errs.As(err)
		return errors.Is(err, errs.ErrRBACGrantExceedsCaller) && e != nil && e.Metadata["permission"] == permission
	}
	asDeveloper := dbtest.Principal(developer.ID, tenant)
	if err := repo.CheckGrantScopes(ctx, asDeveloper, tenant, []string{"user.read", "apikey.write"}); err != nil {
		t.Errorf("a developer issues their own permissions: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, asDeveloper, tenant, []string{"user.read", "role.write"}); !refused(err, "role.write") {
		t.Errorf("a developer issues role.write: %v, want %v naming it", err, errs.ErrRBACGrantExceedsCaller)
	}
	if err := repo.CheckGrantScopes(ctx, asDeveloper, tenant, []string{"vault:read"}); !refused(err, "vault:read") {
		t.Errorf("a developer without secret.read issues vault:read: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, dbtest.Principal(owner.ID, tenant), tenant, []string{"role.write", "tenant.write", "vault:read"}); err != nil {
		t.Errorf("an owner issues anything: %v", err)
	}

	// The owner's own key, narrowly scoped, holds only its scopes.
	ownersKey := &httpx.Principal{UserID: &owner.ID, TenantID: &tenant, ActorType: "api_key", Scopes: []string{"apikey.write", "role.write", "vault:payments"}}
	if err := repo.CheckGrantScopes(ctx, ownersKey, tenant, []string{"role.write", "vault:payments"}); err != nil {
		t.Errorf("a key issues its own scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, ownersKey, tenant, []string{"user.write"}); !refused(err, "user.write") {
		t.Errorf("an owner's key issues beyond its scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, ownersKey, tenant, []string{"vault:read"}); !refused(err, "vault:read") {
		t.Errorf("a key holding one vault secret issues all of them: %v", err)
	}
	if err := repo.CheckGrantRole(ctx, ownersKey, tenant, ownerRole); !errors.Is(err, errs.ErrRBACOwnerOnly) {
		t.Errorf("an owner's key gives the owner role: %v, want %v", err, errs.ErrRBACOwnerOnly)
	}

	// A key outlives a demotion only within what its person still holds.
	developersKey := &httpx.Principal{UserID: &developer.ID, TenantID: &tenant, ActorType: "api_key", Scopes: []string{"apikey.write", "user.read", "role.write"}}
	if err := repo.CheckGrantScopes(ctx, developersKey, tenant, []string{"role.write"}); !refused(err, "role.write") {
		t.Errorf("a key issues a scope its person no longer holds: %v", err)
	}
	service := &httpx.Principal{TenantID: &tenant, ActorType: "service", Scopes: []string{"apikey.write", "vault:read"}}
	if err := repo.CheckGrantScopes(ctx, service, tenant, []string{"vault:payments", "apikey.write"}); err != nil {
		t.Errorf("a service principal issues within its scopes: %v", err)
	}
	if err := repo.CheckGrantScopes(ctx, service, tenant, []string{"secret.read"}); !refused(err, "secret.read") {
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
	tenant := dbtest.Tenant(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, coOwner := dbtest.User(t, tenant), dbtest.User(t, tenant)
	dbtest.Assign(t, owner.ID, tenant, ownerRole)
	dbtest.Assign(t, coOwner.ID, tenant, ownerRole)
	reviewers := dbtest.Role(t, tenant, "audit.read")
	dbtest.Assign(t, coOwner.ID, tenant, reviewers)
	admin := dbtest.User(t, tenant)
	dbtest.Assign(t, admin.ID, tenant, dbtest.Role(t, tenant, "role.read", "role.write", "user.read"))
	var auditRead, roleWrite uuid.UUID
	for key, id := range map[string]*uuid.UUID{"audit.read": &auditRead, "role.write": &roleWrite} {
		if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, key).Scan(id); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{Repo: repo, Service: NewService(repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	as := func(u uuid.UUID) http.Handler { return dbtest.Serve(dbtest.Principal(u, tenant), h.Mount) }
	for _, tc := range []struct {
		name         string
		caller       uuid.UUID
		method, path string
		status       int
		code         string
	}{
		{"an owner revokes from the owner role", owner.ID, http.MethodDelete, "/roles/" + ownerRole.String() + "/permissions/" + roleWrite.String(), http.StatusForbidden, errs.CodeRBACSystemRoleFixed},
		{"an admin grants to the owner role", admin.ID, http.MethodPost, "/roles/" + ownerRole.String() + "/permissions/" + roleWrite.String(), http.StatusForbidden, errs.CodeRBACSystemRoleFixed},
		{"an admin revokes a permission they lack", admin.ID, http.MethodDelete, "/roles/" + reviewers.String() + "/permissions/" + auditRead.String(), http.StatusForbidden, errs.CodeRBACGrantExceedsCaller},
		{"an admin removes an owner's owner role", admin.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/tenants/" + tenant.String() + "/roles/" + ownerRole.String(), http.StatusForbidden, errs.CodeRBACTargetIsOwner},
		{"an admin strips an owner of another role", admin.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/tenants/" + tenant.String() + "/roles/" + reviewers.String(), http.StatusForbidden, errs.CodeRBACTargetIsOwner},
		{"an owner removes a co-owner's owner role", owner.ID, http.MethodDelete, "/users/" + coOwner.ID.String() + "/tenants/" + tenant.String() + "/roles/" + ownerRole.String(), http.StatusNoContent, ""},
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
