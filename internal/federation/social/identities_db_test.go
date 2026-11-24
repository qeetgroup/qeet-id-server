//go:build integration

package social

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestUnlinkingAnOwnersSocialIdentityNeedsToOutrankThem checks that an
// administrator who may unlink members' social sign-ins can't unlink an
// owner's, nor that of a member holding a permission they don't, while an
// owner can.
func TestUnlinkingAnOwnersSocialIdentityNeedsToOutrankThem(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	f := newSocialFixture(t)
	h := &Handler{Service: f.svc, ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', TRUE) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, otherOwner := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, otherOwner.ID, organization, ownerRole)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "user.read", "user.write"))
	billing := dbtest.User(t, organization)
	dbtest.Assign(t, billing.ID, organization, dbtest.Role(t, organization, "billing.write"))
	member := dbtest.User(t, organization, organization)
	if _, err := pool.Exec(ctx, `INSERT INTO organization.social_providers (organization_id, provider, client_id, client_secret_ct, client_secret_nonce) VALUES ($1, 'google', 'id', '\x00', '\x00')`, organization); err != nil {
		t.Fatal(err)
	}
	identity := func(a dbtest.Account) string {
		t.Helper()
		dbtest.SetPassword(t, a.ID, dbtest.Unique("Kx7mQ2vLp9Wz"))
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'google', $3) RETURNING id`,
			a.ID, organization, dbtest.Unique("subject")).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return "/social/identities/" + id.String()
	}
	unlink := func(as dbtest.Account, path string) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as.ID, organization), h.Mount), http.MethodDelete, path, nil)
		return rec.Code, rec.Body.String()
	}

	owners := identity(owner)
	if status, body := unlink(admin, owners); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetIsOwner) {
		t.Errorf("an administrator unlinks an owner's sign-in: %d %s, want 403 %s", status, body, errs.CodeRBACTargetIsOwner)
	}
	if status, body := unlink(admin, identity(billing)); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetOutranks) {
		t.Errorf("an administrator unlinks the sign-in of someone holding billing.write: %d %s, want 403 %s", status, body, errs.CodeRBACTargetOutranks)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = ANY($1)`, []uuid.UUID{owner.ID, billing.ID}); n != 2 {
		t.Errorf("%d of the outranking people's sign-ins left, want both", n)
	}
	if status, body := unlink(admin, identity(member)); status != http.StatusNoContent {
		t.Errorf("an administrator unlinks a member's sign-in: %d %s, want 204", status, body)
	}
	if status, body := unlink(otherOwner, owners); status != http.StatusNoContent {
		t.Errorf("an owner unlinks another owner's sign-in: %d %s, want 204", status, body)
	}
	if status, _ := unlink(admin, "/social/identities/"+uuid.NewString()); status != http.StatusNotFound {
		t.Errorf("unlink an identity that doesn't exist: %d, want 404", status)
	}
}
