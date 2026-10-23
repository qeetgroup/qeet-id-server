//go:build integration

package rbac

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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

// limit is a PlanLimiter allowing n of every resource.
type limit int

func (n limit) Limit(context.Context, uuid.UUID, string) (int, error) { return int(n), nil }

// TestRoleLifecycle checks that a custom role is refused beyond the plan's
// limit; that a permission granted to a role reaches a person given the role
// directly or through a group, and so passes enforcement, until the role, the
// group's role or the permission is taken away; that each change is audited;
// and that a person's role changes are announced.
func TestRoleLifecycle(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	repo := NewRepository(pool)
	svc := NewService(repo)
	var announced []string
	svc.SetEmitter(func(_ context.Context, _ uuid.UUID, eventType string, payload any) error {
		announced = append(announced, eventType+":"+payload.(map[string]any)["change"].(string))
		return nil
	})
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	direct, viaGroup := dbtest.User(t, tenant), dbtest.User(t, tenant)
	actor := audit.Actor{UserID: &admin.ID, Type: "user"}
	const perm = "reports:export"
	dbtest.Role(t, tenant, perm) // makes sure the permission exists
	var permID, groupID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM rbac.permissions WHERE key = $1`, perm).Scan(&permID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenant, dbtest.Unique("group")).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.group_members (tenant_id, group_id, user_id) VALUES ($1, $2, $3)`, tenant, groupID, viaGroup.ID); err != nil {
		t.Fatal(err)
	}
	holds := func(u dbtest.Account) bool {
		t.Helper()
		ok, err := repo.Check(ctx, u.ID, tenant, perm)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	enforced := func(u dbtest.Account) int {
		t.Helper()
		h := dbtest.Serve(dbtest.Principal(u.ID, tenant), func(r chi.Router) {
			r.Use(Enforce(repo, map[string]RoutePolicy{"GET /reports": PermissionPolicy(perm)}))
			r.Get("/reports", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		})
		return dbtest.Do(t, h, http.MethodGet, "/reports", nil).Code
	}
	audited := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND tenant_id = $2`, action, tenant)
	}

	svc.SetPlanLimiter(limit(0))
	if _, err := svc.CreateRole(ctx, tenant, "Analyst", "", actor); !errors.Is(err, errs.ErrPlanLimit) {
		t.Errorf("a custom role over the plan's limit: %v, want %v", err, errs.ErrPlanLimit)
	}
	svc.SetPlanLimiter(limit(5))
	role, err := svc.CreateRole(ctx, tenant, "Analyst", "Reads reports", actor)
	if err != nil || audited("role.created") != 1 {
		t.Fatalf("create role: %+v, %v, audited %d times", role, err, audited("role.created"))
	}
	if err := svc.GrantPermission(ctx, role.ID, permID, actor); err != nil {
		t.Fatalf("grant permission: %v", err)
	}
	if holds(direct) || enforced(direct) != http.StatusForbidden {
		t.Fatal("a person without the role holds its permission")
	}

	if err := svc.AssignRole(ctx, direct.ID, tenant, role.ID, &admin.ID, actor); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := svc.AssignRoleToGroup(ctx, groupID, tenant, role.ID, &admin.ID, actor); err != nil {
		t.Fatalf("assign role to group: %v", err)
	}
	for name, u := range map[string]dbtest.Account{"given the role": direct, "in the group": viaGroup} {
		if !holds(u) || enforced(u) != http.StatusOK {
			t.Errorf("a person %s doesn't hold the role's permission", name)
		}
	}
	if audited("role.assigned") != 1 || audited("role.group_assigned") != 1 {
		t.Error("the role assignments were not audited")
	}

	if err := svc.RemoveRoleFromGroup(ctx, groupID, tenant, role.ID, actor); err != nil {
		t.Fatalf("remove role from group: %v", err)
	}
	if holds(viaGroup) {
		t.Error("a group member kept the permission after the group lost the role")
	}
	if err := svc.RevokePermission(ctx, role.ID, permID, actor); err != nil {
		t.Fatalf("revoke permission: %v", err)
	}
	if holds(direct) || enforced(direct) != http.StatusForbidden {
		t.Error("a person kept a permission revoked from their role")
	}
	if err := svc.UnassignRole(ctx, direct.ID, tenant, role.ID, actor); err != nil || audited("role.unassigned") != 1 {
		t.Errorf("unassign role: %v, audited %d times", err, audited("role.unassigned"))
	}
	if want := []string{"token.claims_change:role_assigned", "token.claims_change:role_unassigned"}; !slices.Equal(announced, want) {
		t.Errorf("announced %v; want %v", announced, want)
	}
}
