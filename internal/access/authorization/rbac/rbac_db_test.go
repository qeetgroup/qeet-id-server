//go:build integration

package rbac

import (
	"net/http"
	"slices"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// TestRolesStayInTheirTenant checks that one tenant can neither read nor change
// another tenant's roles, nor assign them, nor assign its own roles to another
// tenant's user.
func TestRolesStayInTheirTenant(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	const perm = "reports:export"
	roleA := dbtest.Role(t, tenantA, perm)
	roleB := dbtest.Role(t, tenantB)
	userA := dbtest.User(t, tenantA)
	dbtest.Assign(t, userA.ID, tenantA, roleA)
	adminB := dbtest.User(t, tenantB, tenantB)
	memberB := dbtest.User(t, tenantB, tenantB)
	var permID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, perm).Scan(&permID); err != nil {
		t.Fatalf("permission id: %v", err)
	}

	h := &Handler{Repo: repo, Service: NewService(repo), Validate: validator.New(validator.WithRequiredStructEnabled())}
	asB := dbtest.Serve(dbtest.Principal(adminB.ID, tenantB), h.Mount)
	roleAPath := "/roles/" + roleA.String() + "/permissions"
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, roleAPath, http.StatusNotFound},
		{http.MethodPost, roleAPath + "/" + permID.String(), http.StatusNotFound},
		{http.MethodDelete, roleAPath + "/" + permID.String(), http.StatusNotFound},
		{http.MethodPost, "/users/" + memberB.ID.String() + "/tenants/" + tenantB.String() + "/roles/" + roleA.String(), http.StatusNotFound},
		{http.MethodPost, "/users/" + userA.ID.String() + "/tenants/" + tenantB.String() + "/roles/" + roleB.String(), http.StatusNotFound},
		{http.MethodDelete, "/users/" + userA.ID.String() + "/tenants/" + tenantA.String() + "/roles/" + roleA.String(), http.StatusForbidden},
		{http.MethodGet, "/users/" + userA.ID.String() + "/tenants/" + tenantA.String() + "/permissions", http.StatusForbidden},
		{http.MethodGet, "/tenants/" + tenantA.String() + "/roles", http.StatusForbidden},
	} {
		if rec := dbtest.Do(t, asB, tc.method, tc.path, nil); rec.Code != tc.want {
			t.Errorf("tenant B %s %s: status %d, want %d (%s)", tc.method, tc.path, rec.Code, tc.want, rec.Body.String())
		}
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asB, http.MethodGet, "/tenants/"+tenantB.String()+"/roles", nil)); slices.Contains(ids, roleA) {
		t.Error("tenant B's role list includes tenant A's role")
	}

	if ok, err := repo.Check(ctx, userA.ID, tenantA, perm); err != nil || !ok {
		t.Errorf("tenant A's user lost %s: %v, %v", perm, ok, err)
	}
	if ok, err := repo.Check(ctx, memberB.ID, tenantB, perm); err != nil || ok {
		t.Errorf("tenant B's member holds tenant A's %s: %v, %v", perm, ok, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, userA.ID, tenantB); n != 0 {
		t.Error("tenant A's user was given a role in tenant B")
	}
}
