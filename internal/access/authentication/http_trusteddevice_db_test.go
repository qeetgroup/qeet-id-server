//go:build integration

package authentication

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
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
	remember := func(userID uuid.UUID) string {
		t.Helper()
		if _, err := svc.CreateTrustedDevice(ctx, userID, organization, testUserAgent, time.Hour); err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT id FROM auth.trusted_devices WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, userID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return "/users/" + userID.String() + "/trusted-devices/" + id.String()
	}
	forget := func(as dbtest.Account, path string) (int, string) {
		rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(as.ID, organization), h.MountAuthed), http.MethodDelete, path, nil)
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

// TestTrustedDevicesOverHTTP checks the views of remembered devices: a person
// lists theirs in every organization, marked where it is the requesting one,
// and forgets one or all, never another person's; an administrator sees,
// counts and forgets only those remembered in their own organization, and for
// its members only.
func TestTrustedDevicesOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, home := member(t)
	other := dbtest.Organization(t)
	dbtest.Assign(t, a.ID, other, dbtest.Role(t, other))
	colleague := dbtest.User(t, home, home)
	outsider, _ := member(t)
	admin := dbtest.User(t, home, home)
	remember := func(userID, organization uuid.UUID) (string, uuid.UUID) {
		t.Helper()
		raw, err := svc.CreateTrustedDevice(ctx, userID, organization, testUserAgent, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM auth.trusted_devices WHERE token_hash = $1`, tokens.HashRefresh(raw)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return raw, id
	}
	current, atHome := remember(a.ID, home)
	_, atOther := remember(a.ID, other)
	_, colleagues := remember(colleague.ID, home)
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, expires_at)
		VALUES ($1, $2, $3, NOW() - INTERVAL '1 minute')`, a.ID, home, dbtest.Unique("expired")); err != nil {
		t.Fatal(err)
	}
	type listed struct {
		Items []TrustedDevice `json:"items"`
	}
	forgotten := func(rec *httptest.ResponseRecorder) int {
		t.Helper()
		var got struct {
			Forgotten int `json:"forgotten"`
		}
		dbtest.Decode(t, rec, &got)
		if rec.Code != http.StatusOK {
			t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
		}
		return got.Forgotten
	}

	own := newBrowser(t, dbtest.Serve(dbtest.Principal(a.ID, home), newHandler(svc).MountAuthed))
	own.cookies[TrustedDeviceCookie] = &http.Cookie{Name: TrustedDeviceCookie, Value: current}
	var mine listed
	dbtest.Decode(t, own.do(http.MethodGet, "/auth/trusted-devices", nil), &mine)
	marked := map[uuid.UUID]bool{}
	for _, d := range mine.Items {
		marked[d.ID] = d.Current
		if d.Device != "Chrome on macOS" || d.DeviceKind != "desktop" {
			t.Errorf("device named %q (%s), want Chrome on macOS (desktop)", d.Device, d.DeviceKind)
		}
	}
	if len(marked) != 2 || !marked[atHome] || marked[atOther] {
		t.Errorf("own devices %v; want the live ones in both organizations, the requesting one marked", marked)
	}
	if rec := own.do(http.MethodDelete, "/auth/trusted-devices/"+colleagues.String(), nil); !answered(rec, http.StatusNotFound, errs.CodeNotFound) {
		t.Errorf("forget another person's device: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if rec := own.do(http.MethodDelete, "/auth/trusted-devices/not-a-device", nil); !answered(rec, http.StatusBadRequest, errs.CodeBadRequest) {
		t.Errorf("forget a malformed device id: %d, want 400", rec.Code)
	}

	adm := newBrowser(t, dbtest.Serve(dbtest.Principal(admin.ID, home), newHandler(svc).MountAuthed))
	var count TrustedDeviceSummary
	dbtest.Decode(t, adm.do(http.MethodGet, "/auth/trusted-devices/count", nil), &count)
	if count != (TrustedDeviceSummary{Devices: 2, Users: 2}) {
		t.Errorf("organization's device count %+v, want 2 devices of 2 people", count)
	}
	var theirs listed
	dbtest.Decode(t, adm.do(http.MethodGet, "/users/"+a.ID.String()+"/trusted-devices", nil), &theirs)
	if len(theirs.Items) != 1 || theirs.Items[0].ID != atHome || theirs.Items[0].Current {
		t.Errorf("a member's devices as the administrator sees them: %+v, want only the one remembered here", theirs.Items)
	}
	for _, tc := range []struct {
		name, method, path string
		status             int
	}{
		{"list an outsider's devices", http.MethodGet, "/users/" + outsider.ID.String() + "/trusted-devices", http.StatusNotFound},
		{"list for a malformed id", http.MethodGet, "/users/not-a-user/trusted-devices", http.StatusBadRequest},
		{"forget a member's device in another organization", http.MethodDelete, "/users/" + a.ID.String() + "/trusted-devices/" + atOther.String(), http.StatusNotFound},
		{"forget an outsider's devices", http.MethodDelete, "/users/" + outsider.ID.String() + "/trusted-devices", http.StatusNotFound},
		{"forget a malformed device id", http.MethodDelete, "/users/" + a.ID.String() + "/trusted-devices/not-a-device", http.StatusBadRequest},
	} {
		if rec := adm.do(tc.method, tc.path, nil); rec.Code != tc.status {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.status)
		}
	}
	if n := forgotten(adm.do(http.MethodDelete, "/users/"+a.ID.String()+"/trusted-devices/"+atHome.String(), nil)); n != 1 {
		t.Errorf("forget a member's device: %d forgotten, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.trusted_device_revoked' AND resource_id = $1
		AND organization_id = $2 AND actor_user_id = $3`, atHome, home, admin.ID); n != 1 {
		t.Errorf("forgetting the device was audited %d times, want once by the administrator", n)
	}
	if n := forgotten(adm.do(http.MethodDelete, "/users/"+a.ID.String()+"/trusted-devices", nil)); n != 1 {
		t.Errorf("forget all of a member's devices here: %d forgotten, want the expired one left", n)
	}
	if n := forgotten(own.do(http.MethodDelete, "/auth/trusted-devices", nil)); n != 1 {
		t.Errorf("forget all own devices: %d forgotten, want the one in the other organization", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, colleague.ID}); n != 1 {
		t.Errorf("%d devices left, want the colleague's alone", n)
	}
}
