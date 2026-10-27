//go:build integration

package rbac

import (
	"errors"
	"testing"

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
