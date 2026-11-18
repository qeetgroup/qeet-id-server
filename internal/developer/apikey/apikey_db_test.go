//go:build integration

package apikey

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/rotation"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAPIKeysStayInTheirOrganization checks that one organization can neither list nor
// revoke another organization's API key, nor create one acting for its user or in
// its name.
func TestAPIKeysStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	adminA := dbtest.User(t, organizationA, organizationA)
	adminB := dbtest.User(t, organizationB, organizationB)
	keyA, rawA, err := svc.Create(ctx, CreateInput{OrganizationID: organizationA, Name: "ci", Actor: audit.Actor{UserID: &adminA.ID, Type: "user"}})
	if err != nil {
		t.Fatalf("create key in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, organizationB), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	if rec := dbtest.Do(t, asB, http.MethodDelete, "/api-keys/"+keyA.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("organization B revokes organization A's key: status %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationA.String()+"/api-keys", nil); rec.Code != http.StatusForbidden {
		t.Errorf("organization B lists organization A's keys: status %d, want 403", rec.Code)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/organizations/"+organizationB.String()+"/api-keys", nil)); slices.Contains(ids, keyA.ID) {
		t.Error("organization B's key list includes organization A's key")
	}

	// A key created by B lands in B whatever the body says, and may not act
	// for A's user.
	rec := dbtest.Do(t, asB, http.MethodPost, "/api-keys", map[string]any{"name": "b", "organization_id": organizationA})
	var created struct {
		APIKey Key `json:"api_key"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.APIKey.OrganizationID != organizationB {
		t.Errorf("organization B creates a key naming organization A: status %d, organization %s; want 201 in %s", rec.Code, created.APIKey.OrganizationID, organizationB)
	}
	if rec := dbtest.Do(t, asB, http.MethodPost, "/api-keys", map[string]any{"name": "b", "user_id": adminA.ID}); rec.Code == http.StatusCreated {
		t.Error("organization B created a key acting for organization A's user")
	}

	got, err := svc.Verify(ctx, rawA)
	if err != nil || got.OrganizationID != organizationA {
		t.Fatalf("organization A's key after organization B's calls: %+v, %v", got, err)
	}
	if err := svc.Revoke(ctx, organizationB, keyA.ID, audit.Actor{Type: "user"}); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("revoke in organization B: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND organization_id = $2`, adminA.ID, organizationB); n != 0 {
		t.Errorf("organization B holds %d keys acting for organization A's user", n)
	}
}

// TestAPIKeyNameIsAtMost200Characters checks that a key named with more than
// 200 characters is refused, and one of exactly 200 is created.
func TestAPIKeyNameIsAtMost200Characters(t *testing.T) {
	organization := dbtest.Organization(t)
	h := dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization),
		(&Handler{Service: NewService(dbtest.Pool(t)), GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	if rec := dbtest.Do(t, h, http.MethodPost, "/api-keys", map[string]any{"name": strings.Repeat("é", 201)}); rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), errs.CodeValidation) || !strings.Contains(rec.Body.String(), `"field":"name"`) {
		t.Errorf("a 201-character name: %d %s, want 422 %s on name", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/api-keys", map[string]any{"name": strings.Repeat("é", 200)}); rec.Code != http.StatusCreated {
		t.Errorf("a 200-character name: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d keys created, want the one with a 200-character name", n)
	}
}

// TestPersonalKeysStopWithTheirPerson checks that a key acting for a person
// works only while their account is active: not while suspended, again once
// reactivated, and never once deleted. A key acting for no one is unaffected.
func TestPersonalKeysStopWithTheirPerson(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &a.ID, Type: "user"}
	_, personal, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "laptop", UserID: &a.ID, Actor: actor})
	if err != nil {
		t.Fatalf("create a personal key: %v", err)
	}
	_, shared, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "ci", Actor: actor})
	if err != nil {
		t.Fatalf("create a key for no one: %v", err)
	}
	for _, step := range []struct {
		name, change string
		works        bool
	}{
		{"active", `UPDATE account.users SET status = 'active' WHERE id = $1`, true},
		{"suspended", `UPDATE account.users SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE account.users SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, a.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Verify(ctx, personal); (err == nil) != step.works {
			t.Errorf("the personal key of a %s account: %v, want works=%v", step.name, err, step.works)
		}
		if _, err := svc.Verify(ctx, shared); err != nil {
			t.Errorf("a key for no one, its creator %s: %v", step.name, err)
		}
	}
}

// TestRotateReplacesAKeyWithAnOverlap checks that a rotated key's replacement
// carries its scopes, its creator and the key it replaced, that the old key
// works until the overlap ends and stops at once with none, and that only the
// person a personal key acts for may rotate it.
func TestRotateReplacesAKeyWithAnOverlap(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	a, b := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	asA, asB := audit.Actor{UserID: &a.ID, Type: "user"}, audit.Actor{UserID: &b.ID, Type: "user"}
	old, oldRaw, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "ci", Scopes: []string{}, Actor: asA})
	if err != nil {
		t.Fatal(err)
	}
	if old.CreatedBy == nil || *old.CreatedBy != a.ID {
		t.Errorf("a new key's created_by = %v, want %s", old.CreatedBy, a.ID)
	}
	k, raw, err := svc.Rotate(ctx, organization, old.ID, rotation.DefaultOverlap, asB)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if k.Name != "ci" || k.RotatedFrom == nil || *k.RotatedFrom != old.ID || k.CreatedBy == nil || *k.CreatedBy != b.ID {
		t.Errorf("the replacement: %+v, want ci, rotated from %s, created by %s", k, old.ID, b.ID)
	}
	for name, key := range map[string]string{"old": oldRaw, "new": raw} {
		if _, err := svc.Verify(ctx, key); err != nil {
			t.Errorf("the %s key during the overlap: %v", name, err)
		}
	}
	if _, _, err := svc.Rotate(ctx, organization, k.ID, 0, asA); err != nil {
		t.Fatalf("rotate with no overlap: %v", err)
	}
	if _, err := svc.Verify(ctx, raw); err == nil {
		t.Error("a key rotated with no overlap still works")
	}
	if _, _, err := svc.Rotate(ctx, organization, k.ID, time.Hour, asA); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("rotate a revoked key: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
	if _, _, err := svc.Rotate(ctx, organization, old.ID, 8*24*time.Hour, asA); err == nil {
		t.Error("an eight-day overlap was accepted")
	}

	personal, _, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: "laptop", UserID: &a.ID, Actor: asA})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Rotate(ctx, organization, personal.ID, time.Hour, asB); !errors.Is(err, ErrUserNotSelf) {
		t.Errorf("rotate another person's key: %v, want %v", err, ErrUserNotSelf)
	}
	if k, _, err := svc.Rotate(ctx, organization, personal.ID, time.Hour, asA); err != nil || k.UserID == nil || *k.UserID != a.ID {
		t.Errorf("rotate one's own key: %+v, %v", k, err)
	}
	if _, _, err := svc.Rotate(ctx, dbtest.Organization(t), old.ID, time.Hour, asA); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("rotate from another organization: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
}

// TestKeyOfDeletedOrganizationIsRefused checks that an organization's keys,
// personal or not, authenticate only while it is active: not while suspended,
// again once reactivated, and never once deleted, and that Live agrees.
func TestKeyOfDeletedOrganizationIsRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	actor := audit.Actor{UserID: &a.ID, Type: "user"}
	keys := map[string]string{}
	var ids []uuid.UUID
	for name, owner := range map[string]*uuid.UUID{"personal": &a.ID, "shared": nil} {
		k, raw, err := svc.Create(ctx, CreateInput{OrganizationID: organization, Name: name, UserID: owner, Actor: actor})
		if err != nil {
			t.Fatalf("create a %s key: %v", name, err)
		}
		keys[name] = raw
		ids = append(ids, k.ID)
	}
	for _, step := range []struct {
		name, change string
		works        bool
	}{
		{"suspended", `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE organization.organizations SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE organization.organizations SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, organization); err != nil {
			t.Fatal(err)
		}
		for name, raw := range keys {
			if _, err := svc.Verify(ctx, raw); (err == nil) != step.works {
				t.Errorf("a %s key of a %s organization: %v, want works=%v", name, step.name, err, step.works)
			}
		}
		for _, id := range ids {
			if live, err := svc.Live(ctx, organization, id); err != nil || live != step.works {
				t.Errorf("a key of a %s organization: live %v, %v; want %v", step.name, live, err, step.works)
			}
		}
	}
}

// TestAPIKeysCarryOnlyTheCreatorsAuthority checks that a credential is created
// only with scopes its creator holds: a developer can't mint one with role.write.
func TestAPIKeysCarryOnlyTheCreatorsAuthority(t *testing.T) {
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	developer := dbtest.User(t, organization)
	dbtest.Assign(t, developer.ID, organization, dbtest.Role(t, organization, "apikey.write", "user.read"))
	h := dbtest.Serve(dbtest.Principal(developer.ID, organization),
		(&Handler{Service: NewService(pool), GrantCheck: rbac.NewRepository(pool).CheckGrantScopes}).Mount)
	path := "/api-keys"

	body := func(scopes ...string) map[string]any {
		return map[string]any{"name": "ci-deploy", "scopes": scopes}
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read", "role.write")); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), errs.CodeRBACGrantExceedsCaller) || !strings.Contains(rec.Body.String(), "role.write") {
		t.Errorf("create with role.write: %d %s, want 403 %s naming role.write", rec.Code, rec.Body.String(), errs.CodeRBACGrantExceedsCaller)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, body("user.read")); rec.Code != http.StatusCreated {
		t.Errorf("create with the creator's own scope: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE organization_id = $1`, organization); n != 1 {
		t.Errorf("%d credentials stored, want only the permitted one", n)
	}
}
