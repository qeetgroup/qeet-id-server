//go:build integration

package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestRoleAssignmentStaysInsideTheOrganization pins the tenant boundary on
// direct role assignment: an organization's admin can give its own roles to its
// own members, and nothing else. A user from another organization, a role from
// another organization, an id that doesn't exist and a deleted account are all
// refused the same way, write nothing, and leave an audit row behind.
func TestRoleAssignmentStaysInsideTheOrganization(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repo := rbac.NewRepository(testPool)
	svc := rbac.NewService(repo)
	claimsChanges := 0
	svc.SetEmitter(func(_ context.Context, _ uuid.UUID, eventType string, _ any) error {
		if eventType == "token.claims_change" {
			claimsChanges++
		}
		return nil
	})
	actor := audit.Actor{Type: "system"}

	home := createTenant(t, ctx, uniqueSlug("assign-home"))
	other := createTenant(t, ctx, uniqueSlug("assign-other"))

	// adminCreated has this organization as its home but no membership row yet,
	// the state an admin-created account is in before its first role.
	adminCreated := createUserInTenant(t, ctx, home)
	// invited belongs to the other organization and joined this one by invitation.
	invited := createUserInTenant(t, ctx, other)
	addTenantMembership(t, ctx, invited, home)
	// outsider belongs only to the other organization.
	outsider := createUserInTenant(t, ctx, other)
	addTenantMembership(t, ctx, outsider, other)
	deleted := createUserInTenant(t, ctx, home)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET deleted_at = NOW() WHERE id = $1`, deleted); err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	perm, err := repo.UpsertPermission(ctx, tx, "assign-test:write", "assignment test")
	if err != nil {
		t.Fatalf("permission: %v", err)
	}
	homeRole, err := repo.CreateRole(ctx, tx, home, "deployer-"+uniqueSlug("r"), "", false)
	if err != nil {
		t.Fatalf("home role: %v", err)
	}
	homeBuiltIn, err := repo.CreateRole(ctx, tx, home, "built-in-"+uniqueSlug("r"), "", true)
	if err != nil {
		t.Fatalf("home built-in role: %v", err)
	}
	otherRole, err := repo.CreateRole(ctx, tx, other, "other-secret-"+uniqueSlug("r"), "Other organization internal", false)
	if err != nil {
		t.Fatalf("other role: %v", err)
	}
	for _, roleID := range []uuid.UUID{homeRole.ID, otherRole.ID} {
		if err := repo.GrantPermission(ctx, tx, roleID, perm.ID); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("setup commit: %v", err)
	}

	rows := func(userID, roleID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`,
			userID, home, roleID).Scan(&n); err != nil {
			t.Fatalf("count user_roles: %v", err)
		}
		return n
	}
	audits := func(action string, userID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2 AND resource_id = $3`,
			home, action, userID).Scan(&n); err != nil {
			t.Fatalf("count audit events: %v", err)
		}
		return n
	}

	t.Run("a member is given the organization's own role", func(t *testing.T) {
		before := claimsChanges
		if err := svc.AssignRole(ctx, invited, home, homeRole.ID, nil, actor); err != nil {
			t.Fatalf("assign: %v", err)
		}
		if ok, _ := repo.Check(ctx, invited, home, perm.Key); !ok {
			t.Fatal("the member does not hold the role's permission")
		}
		if audits("role.assigned", invited) != 1 {
			t.Fatal("no role.assigned audit row")
		}
		if claimsChanges != before+1 {
			t.Fatal("no token.claims_change for a real assignment")
		}
	})

	t.Run("assigning a role the member already holds still succeeds", func(t *testing.T) {
		if err := svc.AssignRole(ctx, invited, home, homeRole.ID, nil, actor); err != nil {
			t.Fatalf("repeat assign: %v", err)
		}
		if n := rows(invited, homeRole.ID); n != 1 {
			t.Fatalf("rows = %d, want 1", n)
		}
	})

	t.Run("an admin-created user is given a role in their home organization", func(t *testing.T) {
		if err := svc.AssignRole(ctx, adminCreated, home, homeRole.ID, nil, actor); err != nil {
			t.Fatalf("assign: %v", err)
		}
	})

	t.Run("a built-in role of the same organization can be given", func(t *testing.T) {
		if err := svc.AssignRole(ctx, adminCreated, home, homeBuiltIn.ID, nil, actor); err != nil {
			t.Fatalf("assign built-in: %v", err)
		}
	})

	refusals := []struct {
		name   string
		userID uuid.UUID
		roleID uuid.UUID
	}{
		{"a user from another organization", outsider, homeRole.ID},
		{"a role from another organization", adminCreated, otherRole.ID},
		{"a user id that does not exist", uuid.New(), homeRole.ID},
		{"a role id that does not exist", adminCreated, uuid.New()},
		{"a deleted user", deleted, homeRole.ID},
	}
	var bodies []string
	for _, c := range refusals {
		t.Run("refuses "+c.name, func(t *testing.T) {
			before := claimsChanges
			assignedBefore := audits("role.assigned", c.userID)
			refusedBefore := audits("role.assign_refused", c.userID)
			err := svc.AssignRole(ctx, c.userID, home, c.roleID, nil, actor)
			if !errors.Is(err, errs.ErrRBACUserOrRoleNotFound) {
				t.Fatalf("err = %v, want %v", err, errs.ErrRBACUserOrRoleNotFound)
			}
			if n := rows(c.userID, c.roleID); n != 0 {
				t.Fatalf("a refused assignment wrote %d row(s)", n)
			}
			if audits("role.assigned", c.userID) != assignedBefore {
				t.Fatal("a refused assignment was audited as role.assigned")
			}
			if audits("role.assign_refused", c.userID) != refusedBefore+1 {
				t.Fatal("no role.assign_refused audit row")
			}
			if claimsChanges != before {
				t.Fatal("a refused assignment sent token.claims_change")
			}
			rec := httptest.NewRecorder()
			httpx.WriteError(rec, httptest.NewRequest(http.MethodPost, "/", nil), err)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			bodies = append(bodies, rec.Body.String())
		})
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("refusals are distinguishable:\n%s\n%s", bodies[0], bodies[i])
		}
	}

	t.Run("the outsider did not join the organization", func(t *testing.T) {
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, outsider, home).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("outsider holds %d row(s) in the organization", n)
		}
		if ok, _ := repo.Check(ctx, outsider, home, perm.Key); ok {
			t.Fatal("outsider holds the permission in the organization")
		}
	})

	t.Run("a foreign-role row written before the fix can still be removed", func(t *testing.T) {
		if _, err := testPool.Exec(ctx,
			`INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
			adminCreated, home, otherRole.ID); err != nil {
			t.Fatalf("seed foreign-role row: %v", err)
		}
		if err := svc.UnassignRole(ctx, adminCreated, home, otherRole.ID, actor); err != nil {
			t.Fatalf("unassign: %v", err)
		}
		if n := rows(adminCreated, otherRole.ID); n != 0 {
			t.Fatalf("foreign-role row still present: %d", n)
		}
	})

	t.Run("unassigning in one organization leaves another's assignments alone", func(t *testing.T) {
		if err := svc.AssignRole(ctx, outsider, other, otherRole.ID, nil, actor); err != nil {
			t.Fatalf("assign in the other organization: %v", err)
		}
		if err := svc.UnassignRole(ctx, outsider, home, otherRole.ID, actor); err != nil {
			t.Fatalf("unassign: %v", err)
		}
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2 AND role_id = $3`,
			outsider, other, otherRole.ID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatal("unassigning in this organization removed the other organization's assignment")
		}
	})
}
