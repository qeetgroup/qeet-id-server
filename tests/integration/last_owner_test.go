//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestAnOrganisationKeepsAnActiveOwner: creating an organisation makes its
// creator its owner, and nothing counted the owners afterwards — the only one
// could be suspended, deleted or stripped of the role, even by themselves,
// leaving an organisation nobody can administer. Every such change is now
// refused while it would leave no active owner (409 tenant.last_owner), a
// suspended owner doesn't count, two concurrent removals can't both pass, and
// handing ownership over (make someone else an owner, then remove the old one)
// works and is audited.
func TestAnOrganisationKeepsAnActiveOwner(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	roles := rbac.NewService(rbac.NewRepository(testPool))
	orgs := tenant.NewRepository(testPool)

	// owned is a new organisation and its sole owner, and its owner role.
	owned := func(t *testing.T) (orgID, ownerID, ownerRole uuid.UUID) {
		t.Helper()
		if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (email) VALUES ($1) RETURNING id`,
			uniqueSlug("owner")+"@example.com").Scan(&ownerID); err != nil {
			t.Fatal(err)
		}
		org, err := orgs.CreateWithOwner(ctx, tenant.CreateInput{Slug: uniqueSlug("owned"), Name: "Owned"}, ownerID)
		if err != nil {
			t.Fatal(err)
		}
		if err := testPool.QueryRow(ctx, `SELECT id FROM rbac.roles WHERE tenant_id = $1 AND is_system AND name = 'owner'`, org.ID).Scan(&ownerRole); err != nil {
			t.Fatal(err)
		}
		return org.ID, ownerID, ownerRole
	}
	actor := func(id uuid.UUID) audit.Actor { return audit.Actor{UserID: &id, Type: "user"} }
	suspend := func(id uuid.UUID) error {
		s := "suspended"
		_, err := users.Update(ctx, id, user.UpdateInput{Status: &s})
		return err
	}
	softDelete := func(id uuid.UUID) error {
		tx, err := testPool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := users.SoftDeleteByTx(ctx, tx, id, &id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	status := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		var s string
		if err := testPool.QueryRow(ctx, `SELECT status FROM "user".users WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		if !pgxerr.IsLastOwner(err) {
			t.Fatalf("%s = %v, want the last-owner refusal", what, err)
		}
	}

	t.Run("the only owner can't be suspended, deleted or stripped of the role, even by themselves", func(t *testing.T) {
		org, owner, ownerRole := owned(t)
		refused(t, "suspend", suspend(owner))
		refused(t, "soft delete by themselves", softDelete(owner))
		refused(t, "unassign the owner role", roles.UnassignRole(ctx, owner, org, ownerRole, actor(owner)))
		if got := status(t, owner); got != "active" {
			t.Fatalf("owner status = %q after the refusals, want active (nothing written)", got)
		}

		rr := httptest.NewRecorder()
		httpx.WriteError(rr, httptest.NewRequest(http.MethodDelete, "/v1/users/x", nil), softDelete(owner))
		var body struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &body)
		if rr.Code != http.StatusConflict || body.Error.Code != "tenant.last_owner" {
			t.Fatalf("the API answers %d %q, want 409 tenant.last_owner", rr.Code, body.Error.Code)
		}
	})

	t.Run("handing ownership over, then removing the old owner, works and is audited", func(t *testing.T) {
		org, old, ownerRole := owned(t)
		heir := createUserInTenant(t, ctx, org)
		if err := roles.AssignRole(ctx, heir, org, ownerRole, &old, actor(old)); err != nil {
			t.Fatalf("make the heir an owner: %v", err)
		}
		if err := roles.UnassignRole(ctx, old, org, ownerRole, actor(old)); err != nil {
			t.Fatalf("remove the old owner: %v", err)
		}
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1
			AND ((action = 'role.assigned' AND resource_id = $2) OR (action = 'role.unassigned' AND resource_id = $3))`,
			org, heir, old).Scan(&n); err != nil || n != 2 {
			t.Fatalf("audit has %d of the two steps (%v)", n, err)
		}
		refused(t, "suspend the heir, now the only owner", suspend(heir))
	})

	t.Run("one of two owners can be deleted, and a deleted owner purged", func(t *testing.T) {
		org, first, ownerRole := owned(t)
		second := createUserInTenant(t, ctx, org)
		if err := roles.AssignRole(ctx, second, org, ownerRole, &first, actor(first)); err != nil {
			t.Fatal(err)
		}
		if err := softDelete(first); err != nil {
			t.Fatalf("delete one of two owners: %v", err)
		}
		if err := users.Purge(ctx, first); err != nil {
			t.Fatalf("purge the deleted owner while another is active: %v", err)
		}
	})

	t.Run("a suspended owner doesn't count", func(t *testing.T) {
		org, active, ownerRole := owned(t)
		dormant := createUserInTenant(t, ctx, org)
		if err := roles.AssignRole(ctx, dormant, org, ownerRole, &active, actor(active)); err != nil {
			t.Fatal(err)
		}
		if err := suspend(dormant); err != nil {
			t.Fatal(err)
		}
		refused(t, "suspend the only active owner", suspend(active))
	})

	t.Run("two owners removed at once: at most one goes", func(t *testing.T) {
		org, a, ownerRole := owned(t)
		b := createUserInTenant(t, ctx, org)
		if err := roles.AssignRole(ctx, b, org, ownerRole, &a, actor(a)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, id := range []uuid.UUID{a, b} {
			wg.Add(1)
			go func(i int, id uuid.UUID) {
				defer wg.Done()
				results[i] = softDelete(id)
			}(i, id)
		}
		wg.Wait()
		ok := 0
		for _, err := range results {
			switch {
			case err == nil:
				ok++
			case !pgxerr.IsLastOwner(err):
				t.Fatalf("concurrent removal failed otherwise: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d of the two concurrent removals went through, want exactly one", ok)
		}
	})

	t.Run("once the organisation is deleted its last owner can go", func(t *testing.T) {
		org, owner, _ := owned(t)
		if err := orgs.SoftDelete(ctx, org, nil); err != nil {
			t.Fatalf("delete the organisation: %v", err)
		}
		if err := softDelete(owner); err != nil {
			t.Fatalf("delete the owner of a deleted organisation: %v", err)
		}
	})
}
