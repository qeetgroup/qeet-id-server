//go:build integration

package rbac

import (
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestPersonalAPIKeyLosesWhatItsOwnerLost checks that a key acting for a
// person does only what both its scopes and the person's permissions now
// allow: once they lose a permission, so does the key, a vault read needs
// their secret.read, and a key acting for no one is unaffected.
func TestPersonalAPIKeyLosesWhatItsOwnerLost(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	repo := NewRepository(pool)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization)
	dbtest.Assign(t, person.ID, organization, dbtest.Role(t, organization, "user.read", "secret.read"))
	scopes := []string{"user.read", "vault:database"}
	personal := &httpx.Principal{ActorType: "api_key", Subject: uuid.NewString(), UserID: &person.ID, OrganizationID: &organization, Scopes: scopes}
	shared := &httpx.Principal{ActorType: "api_key", Subject: uuid.NewString(), OrganizationID: &organization, Scopes: scopes}
	users, vault, writes := PermissionPolicy("user.read"), HandlerAuthorizedPolicy(true, "vault:read"), PermissionPolicy("user.write")
	allows := func(p *httpx.Principal, policy RoutePolicy) bool {
		t.Helper()
		ok, err := Allows(ctx, repo, p, policy)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if !allows(personal, users) || !allows(personal, vault) {
		t.Fatal("a personal key whose person holds its scopes is refused")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, person.ID, organization); err != nil {
		t.Fatal(err)
	}
	dbtest.Assign(t, person.ID, organization, dbtest.Role(t, organization, "user.write"))
	if allows(personal, users) {
		t.Error("a personal key reads users after its person lost user.read")
	}
	if allows(personal, vault) {
		t.Error("a personal key reads the vault after its person lost secret.read")
	}
	if allows(personal, writes) {
		t.Error("a personal key writes users with a permission its person holds but the key was never given")
	}
	if !allows(shared, users) || !allows(shared, vault) {
		t.Error("a key acting for no one lost its scopes with someone else's demotion")
	}
}
