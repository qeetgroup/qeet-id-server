//go:build integration

package mfa

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestRemovingAnOwnersPushDeviceNeedsToOutrankThem checks that an
// administrator who may remove members' phones can't remove an owner's, nor
// that of a member holding a permission they don't, while an owner can.
func TestRemovingAnOwnersPushDeviceNeedsToOutrankThem(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc, _ := services(t, notifier.LogSender{})
	h := &Handler{Service: svc, ActOnCheck: rbac.NewRepository(pool).CheckActOn}
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', TRUE) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, otherOwner := dbtest.User(t, organization), dbtest.User(t, organization)
	dbtest.Assign(t, owner.ID, organization, ownerRole)
	dbtest.Assign(t, otherOwner.ID, organization, ownerRole)
	admin := dbtest.User(t, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "user.read", "user.credentials"))
	billing := dbtest.User(t, organization)
	dbtest.Assign(t, billing.ID, organization, dbtest.Role(t, organization, "billing.write"))
	member := dbtest.User(t, organization, organization)
	phone := func(userID uuid.UUID) string {
		t.Helper()
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO auth.mfa_push_devices (user_id, platform, push_token_ct, push_token_nonce, push_token_hash, device_token_hash) VALUES ($1, 'ios', '\x00', '\x00', 'push', $2) RETURNING id`,
			userID, dbtest.Unique("device")).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return "/users/" + userID.String() + "/push-devices/" + id.String()
	}
	remove := func(as dbtest.Account, path string) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as.ID, organization), h.MountAdmin), http.MethodDelete, path, nil)
		return rec.Code, rec.Body.String()
	}

	ownersPhone := phone(owner.ID)
	if status, body := remove(admin, ownersPhone); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetIsOwner) {
		t.Errorf("an administrator removes an owner's phone: %d %s, want 403 %s", status, body, errs.CodeRBACTargetIsOwner)
	}
	if status, body := remove(admin, phone(billing.ID)); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetOutranks) {
		t.Errorf("an administrator removes the phone of someone holding billing.write: %d %s, want 403 %s", status, body, errs.CodeRBACTargetOutranks)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = ANY($1)`, []uuid.UUID{owner.ID, billing.ID}); n != 2 {
		t.Errorf("%d of the outranking people's phones left, want both", n)
	}
	if status, body := remove(admin, phone(member.ID)); status != http.StatusNoContent {
		t.Errorf("an administrator removes a member's phone: %d %s, want 204", status, body)
	}
	if status, body := remove(otherOwner, ownersPhone); status != http.StatusNoContent {
		t.Errorf("an owner removes another owner's phone: %d %s, want 204", status, body)
	}
}
