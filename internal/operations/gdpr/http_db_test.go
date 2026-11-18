//go:build integration

package gdpr

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// passwordCheck re-verifies the account's password as want.
type passwordCheck struct{ want string }

func (c passwordCheck) ReauthPassword(_ context.Context, _ uuid.UUID, plain string) (bool, bool, error) {
	return true, plain == c.want, nil
}

// TestDeleteOwnAccount checks that a person deletes their own account at once,
// only with their password when they have one.
func TestDeleteOwnAccount(t *testing.T) {
	organization := dbtest.Organization(t)
	a := account(t, organization)
	h := dbtest.Serve(dbtest.Principal(a.ID, organization), (&Handler{Service: NewService(dbtest.Pool(t), 0), Reauth: passwordCheck{"Kx7mQ2vLp9Wz"}}).Mount)
	if rec := dbtest.Do(t, h, http.MethodPost, "/account/delete", map[string]string{"password": "wrong"}); rec.Code != http.StatusBadRequest || erased(t, a.ID) {
		t.Errorf("delete with the wrong password: %d", rec.Code)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/account/delete", map[string]string{"password": "Kx7mQ2vLp9Wz"}); rec.Code != http.StatusNoContent || !erased(t, a.ID) {
		t.Errorf("delete with the password: %d, erased %v", rec.Code, erased(t, a.ID))
	}
}

// TestDataRequestsRefusedForSomeoneWhoOutranksTheCaller checks that erasing or
// exporting someone follows the rule for deleting their account: an
// administrator neither erases nor exports a co-owner, nor reads an export of
// one an owner asked for, while an owner exports an administrator.
func TestDataRequestsRefusedForSomeoneWhoOutranksTheCaller(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	var ownerRole uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO rbac.roles (organization_id, name, is_system) VALUES ($1, 'owner', true) RETURNING id`, organization).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	owner, coOwner := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	for _, a := range []dbtest.Account{owner, coOwner} {
		dbtest.Assign(t, a.ID, organization, ownerRole)
	}
	admin := dbtest.User(t, organization, organization)
	dbtest.Assign(t, admin.ID, organization, dbtest.Role(t, organization, "gdpr.write", "gdpr.read", "user.write", "user.delete"))
	h := requests(t, NewService(pool, time.Hour))
	as := func(a dbtest.Account, method, path string, body any) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), h.Mount), method, path, body)
		return rec.Code, rec.Body.String()
	}

	for path, table := range map[string]string{"/gdpr/purge": "purge_requests", "/gdpr/export": "export_requests"} {
		if status, body := as(admin, http.MethodPost, path, map[string]any{"user_id": coOwner.ID}); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetIsOwner) {
			t.Errorf("an administrator asks %s of a co-owner: %d %s, want 403 %s", path, status, body, errs.CodeRBACTargetIsOwner)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM account.`+table+` WHERE organization_id = $1 AND user_id = $2`, organization, coOwner.ID); n != 0 {
			t.Errorf("%d %s rows for the co-owner, want none", n, table)
		}
	}
	if status, body := as(owner, http.MethodPost, "/gdpr/export", map[string]any{"user_id": admin.ID}); status != http.StatusAccepted {
		t.Errorf("an owner exports an administrator: %d %s, want 202", status, body)
	}
	status, body := as(owner, http.MethodPost, "/gdpr/export", map[string]any{"user_id": coOwner.ID})
	if status != http.StatusAccepted {
		t.Fatalf("an owner exports a co-owner: %d %s, want 202", status, body)
	}
	var export struct{ ID uuid.UUID }
	if err := pool.QueryRow(ctx, `SELECT id FROM account.export_requests WHERE organization_id = $1 AND user_id = $2`, organization, coOwner.ID).Scan(&export.ID); err != nil {
		t.Fatal(err)
	}
	if status, body := as(admin, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/export/"+export.ID.String(), nil); status != http.StatusForbidden || !strings.Contains(body, errs.CodeRBACTargetIsOwner) {
		t.Errorf("an administrator reads an export of a co-owner: %d %s, want 403 %s", status, body, errs.CodeRBACTargetIsOwner)
	}
}
