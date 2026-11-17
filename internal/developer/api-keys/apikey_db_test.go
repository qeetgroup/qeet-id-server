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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestAPIKeysStayInTheirTenant checks that one tenant can neither list nor
// revoke another tenant's API key, nor create one acting for its user or in
// its name.
func TestAPIKeysStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t))
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	adminA := dbtest.User(t, tenantA, tenantA)
	adminB := dbtest.User(t, tenantB, tenantB)
	keyA, rawA, err := svc.Create(ctx, CreateInput{TenantID: tenantA, Name: "ci", Actor: audit.Actor{UserID: &adminA.ID, Type: "user"}})
	if err != nil {
		t.Fatalf("create key in A: %v", err)
	}

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc, GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	if rec := dbtest.Do(t, asB, http.MethodDelete, "/api-keys/"+keyA.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("tenant B revokes tenant A's key: status %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantA.String()+"/api-keys", nil); rec.Code != http.StatusForbidden {
		t.Errorf("tenant B lists tenant A's keys: status %d, want 403", rec.Code)
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/api-keys", nil)); slices.Contains(ids, keyA.ID) {
		t.Error("tenant B's key list includes tenant A's key")
	}

	// A key created by B lands in B whatever the body says, and may not act
	// for A's user.
	rec := dbtest.Do(t, asB, http.MethodPost, "/api-keys", map[string]any{"name": "b", "tenant_id": tenantA})
	var created struct {
		APIKey Key `json:"api_key"`
	}
	dbtest.Decode(t, rec, &created)
	if rec.Code != http.StatusCreated || created.APIKey.TenantID != tenantB {
		t.Errorf("tenant B creates a key naming tenant A: status %d, tenant %s; want 201 in %s", rec.Code, created.APIKey.TenantID, tenantB)
	}
	if rec := dbtest.Do(t, asB, http.MethodPost, "/api-keys", map[string]any{"name": "b", "user_id": adminA.ID}); rec.Code == http.StatusCreated {
		t.Error("tenant B created a key acting for tenant A's user")
	}

	got, err := svc.Verify(ctx, rawA)
	if err != nil || got.TenantID != tenantA {
		t.Fatalf("tenant A's key after tenant B's calls: %+v, %v", got, err)
	}
	if err := svc.Revoke(ctx, tenantB, keyA.ID, audit.Actor{Type: "user"}); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("revoke in tenant B: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE user_id = $1 AND tenant_id = $2`, adminA.ID, tenantB); n != 0 {
		t.Errorf("tenant B holds %d keys acting for tenant A's user", n)
	}
}

// TestAPIKeyNameIsAtMost200Characters checks that a key named with more than
// 200 characters is refused, and one of exactly 200 is created.
func TestAPIKeyNameIsAtMost200Characters(t *testing.T) {
	tenant := dbtest.Tenant(t)
	h := dbtest.Serve(dbtest.Principal(dbtest.User(t, tenant, tenant).ID, tenant),
		(&Handler{Service: NewService(dbtest.Pool(t)), GrantCheck: rbac.NewRepository(dbtest.Pool(t)).CheckGrantScopes}).Mount)
	if rec := dbtest.Do(t, h, http.MethodPost, "/api-keys", map[string]any{"name": strings.Repeat("é", 201)}); rec.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rec.Body.String(), errs.CodeValidation) || !strings.Contains(rec.Body.String(), `"field":"name"`) {
		t.Errorf("a 201-character name: %d %s, want 422 %s on name", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/api-keys", map[string]any{"name": strings.Repeat("é", 200)}); rec.Code != http.StatusCreated {
		t.Errorf("a 200-character name: %d %s, want 201", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.api_keys WHERE tenant_id = $1`, tenant); n != 1 {
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
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	actor := audit.Actor{UserID: &a.ID, Type: "user"}
	_, personal, err := svc.Create(ctx, CreateInput{TenantID: tenant, Name: "laptop", UserID: &a.ID, Actor: actor})
	if err != nil {
		t.Fatalf("create a personal key: %v", err)
	}
	_, shared, err := svc.Create(ctx, CreateInput{TenantID: tenant, Name: "ci", Actor: actor})
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
	tenant := dbtest.Tenant(t)
	a, b := dbtest.User(t, tenant, tenant), dbtest.User(t, tenant, tenant)
	asA, asB := audit.Actor{UserID: &a.ID, Type: "user"}, audit.Actor{UserID: &b.ID, Type: "user"}
	old, oldRaw, err := svc.Create(ctx, CreateInput{TenantID: tenant, Name: "ci", Scopes: []string{}, Actor: asA})
	if err != nil {
		t.Fatal(err)
	}
	if old.CreatedBy == nil || *old.CreatedBy != a.ID {
		t.Errorf("a new key's created_by = %v, want %s", old.CreatedBy, a.ID)
	}
	k, raw, err := svc.Rotate(ctx, tenant, old.ID, DefaultRotationOverlap, asB)
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
	if _, _, err := svc.Rotate(ctx, tenant, k.ID, 0, asA); err != nil {
		t.Fatalf("rotate with no overlap: %v", err)
	}
	if _, err := svc.Verify(ctx, raw); err == nil {
		t.Error("a key rotated with no overlap still works")
	}
	if _, _, err := svc.Rotate(ctx, tenant, k.ID, time.Hour, asA); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("rotate a revoked key: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
	if _, _, err := svc.Rotate(ctx, tenant, old.ID, 8*24*time.Hour, asA); err == nil {
		t.Error("an eight-day overlap was accepted")
	}

	personal, _, err := svc.Create(ctx, CreateInput{TenantID: tenant, Name: "laptop", UserID: &a.ID, Actor: asA})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Rotate(ctx, tenant, personal.ID, time.Hour, asB); !errors.Is(err, errs.ErrAPIKeyUserNotSelf) {
		t.Errorf("rotate another person's key: %v, want %v", err, errs.ErrAPIKeyUserNotSelf)
	}
	if k, _, err := svc.Rotate(ctx, tenant, personal.ID, time.Hour, asA); err != nil || k.UserID == nil || *k.UserID != a.ID {
		t.Errorf("rotate one's own key: %+v, %v", k, err)
	}
	if _, _, err := svc.Rotate(ctx, dbtest.Tenant(t), old.ID, time.Hour, asA); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("rotate from another tenant: %v, want %v", err, errs.ErrAPIKeyNotFound)
	}
}

// TestKeyOfDeletedOrganisationIsRefused checks that an organisation's keys,
// personal or not, authenticate only while it is active: not while suspended,
// again once reactivated, and never once deleted, and that Live agrees.
func TestKeyOfDeletedOrganisationIsRefused(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	actor := audit.Actor{UserID: &a.ID, Type: "user"}
	keys := map[string]string{}
	var ids []uuid.UUID
	for name, owner := range map[string]*uuid.UUID{"personal": &a.ID, "shared": nil} {
		k, raw, err := svc.Create(ctx, CreateInput{TenantID: tenant, Name: name, UserID: owner, Actor: actor})
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
		{"suspended", `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, false},
		{"reactivated", `UPDATE tenant.tenants SET status = 'active' WHERE id = $1`, true},
		{"deleted", `UPDATE tenant.tenants SET deleted_at = NOW() WHERE id = $1`, false},
	} {
		if _, err := pool.Exec(ctx, step.change, tenant); err != nil {
			t.Fatal(err)
		}
		for name, raw := range keys {
			if _, err := svc.Verify(ctx, raw); (err == nil) != step.works {
				t.Errorf("a %s key of a %s organisation: %v, want works=%v", name, step.name, err, step.works)
			}
		}
		for _, id := range ids {
			if live, err := svc.Live(ctx, tenant, id); err != nil || live != step.works {
				t.Errorf("a key of a %s organisation: live %v, %v; want %v", step.name, live, err, step.works)
			}
		}
	}
}
