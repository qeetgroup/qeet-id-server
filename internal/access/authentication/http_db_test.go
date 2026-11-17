//go:build integration

package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestForgettingAnOwnersTrustedDevicesNeedsToOutrankThem checks that an
// administrator who may forget members' remembered devices can't forget an
// owner's, nor those of a member holding a permission they don't, one or all,
// while an owner can.
func TestForgettingAnOwnersTrustedDevicesNeedsToOutrankThem(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := newService(t)
	h := newHandler(svc)
	tenant := dbtest.Tenant(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (tenant_id, name, is_system) VALUES ($1, 'owner', TRUE) RETURNING id`, tenant).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, otherOwner := dbtest.User(t, tenant), dbtest.User(t, tenant)
	dbtest.Assign(t, owner.ID, tenant, ownerRole)
	dbtest.Assign(t, otherOwner.ID, tenant, ownerRole)
	admin := dbtest.User(t, tenant)
	dbtest.Assign(t, admin.ID, tenant, dbtest.Role(t, tenant, "user.read", "user.credentials"))
	billing := dbtest.User(t, tenant)
	dbtest.Assign(t, billing.ID, tenant, dbtest.Role(t, tenant, "billing.write"))
	member := dbtest.User(t, tenant, tenant)
	remember := func(userID uuid.UUID) string {
		t.Helper()
		if _, err := svc.CreateTrustedDevice(ctx, userID, tenant, testUserAgent, time.Hour); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM auth.trusted_devices WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, userID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return "/users/" + userID.String() + "/trusted-devices/" + id.String()
	}
	forget := func(as dbtest.Account, path string) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as.ID, tenant), h.MountAuthed), http.MethodDelete, path, nil)
		return rec.Code, rec.Body.String()
	}

	owners := remember(owner.ID)
	for name, c := range map[string]struct {
		path, code string
	}{
		"one of an owner's devices":                    {owners, errs.CodeRBACTargetIsOwner},
		"all of an owner's devices":                    {"/users/" + owner.ID.String() + "/trusted-devices", errs.CodeRBACTargetIsOwner},
		"a device of someone holding billing.write":    {remember(billing.ID), errs.CodeRBACTargetOutranks},
		"all devices of someone holding billing.write": {"/users/" + billing.ID.String() + "/trusted-devices", errs.CodeRBACTargetOutranks},
	} {
		if status, body := forget(admin, c.path); status != http.StatusForbidden || !strings.Contains(body, c.code) {
			t.Errorf("an administrator forgets %s: %d %s, want 403 %s", name, status, body, c.code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = ANY($1)`, []uuid.UUID{owner.ID, billing.ID}); n != 2 {
		t.Errorf("%d of the outranking people's devices left, want both", n)
	}
	if status, body := forget(admin, remember(member.ID)); status != http.StatusOK {
		t.Errorf("an administrator forgets a member's device: %d %s, want 200", status, body)
	}
	if status, body := forget(otherOwner, owners); status != http.StatusOK {
		t.Errorf("an owner forgets another owner's device: %d %s, want 200", status, body)
	}
}
