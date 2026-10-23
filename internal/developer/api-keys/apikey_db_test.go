//go:build integration

package apikey

import (
	"errors"
	"net/http"
	"slices"
	"testing"

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

	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), (&Handler{Service: svc}).Mount)
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
