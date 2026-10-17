//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// Remembered devices can be listed and forgotten by their owner and by an
// administrator of the organisation that remembered them; trust stays with
// that organisation and lasts as long as it says; a changed password or a
// factor reset forgets every device; each is audited when remembered, used
// and forgotten; and expired ones are cleaned up.

const uaIPhone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

func newDeviceAuth() *auth.Service {
	svc, _ := newAuth()
	svc.SetDevicePolicy(authpolicy.NewService(testPool))
	return svc
}

func rememberDevice(t *testing.T, ctx context.Context, svc *auth.Service, userID, tenantID uuid.UUID, ua string) string {
	t.Helper()
	raw, err := svc.CreateTrustedDevice(ctx, userID, tenantID, ua, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("remember device: %v", err)
	}
	return raw
}

func deviceAuditCount(t *testing.T, ctx context.Context, userID uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = $2`,
		userID, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestOwnerListsAndForgetsTrustedDevices: the owner sees each remembered
// device named, the one they are on marked, and can forget one or all; a
// forgotten device skips nothing at its next sign-in.
func TestOwnerListsAndForgetsTrustedDevices(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("devices"))
	userID := createUserInTenant(t, ctx, tenantID)
	laptop := rememberDevice(t, ctx, svc, userID, tenantID, uaChromeMac)
	phone := rememberDevice(t, ctx, svc, userID, tenantID, uaIPhone)

	list, err := svc.ListTrustedDevices(ctx, userID, nil, laptop)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %v (%d devices)", err, len(list))
	}
	var current *auth.TrustedDevice
	for i := range list {
		if list[i].Current {
			current = &list[i]
		}
	}
	if current == nil || current.Device != "Chrome on macOS" || current.DeviceKind != "desktop" {
		t.Fatalf("the device the request came from must be marked and named: %+v", list)
	}

	n, err := svc.ForgetTrustedDevices(ctx, auth.ForgetTrustedDevicesInput{UserID: userID, DeviceID: &current.ID,
		Actor: audit.Actor{UserID: &userID, Type: "user"}})
	if err != nil || n != 1 {
		t.Fatalf("forget one: %v (%d)", err, n)
	}
	if svc.IsTrustedDevice(ctx, userID, tenantID, laptop) {
		t.Fatal("a forgotten device must not skip the second factor")
	}
	if !svc.IsTrustedDevice(ctx, userID, tenantID, phone) {
		t.Fatal("a device not forgotten must still be remembered")
	}
	if _, err := svc.ForgetTrustedDevices(ctx, auth.ForgetTrustedDevicesInput{UserID: userID,
		Actor: audit.Actor{UserID: &userID, Type: "user"}}); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.ListTrustedDevices(ctx, userID, nil, ""); len(list) != 0 {
		t.Fatalf("forgetting all left %d devices", len(list))
	}
	for _, action := range []string{"auth.trusted_device_added", "auth.trusted_device_used", "auth.trusted_device_revoked"} {
		if deviceAuditCount(t, ctx, userID, action) == 0 {
			t.Errorf("%s was not audited", action)
		}
	}
}

// TestTrustStaysWithItsOrganisation: a device remembered in one organisation
// skips nothing in another, even one that also remembers devices.
func TestTrustStaysWithItsOrganisation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	home, other := createTenant(t, ctx, uniqueSlug("devices-home")), createTenant(t, ctx, uniqueSlug("devices-other"))
	userID := createUserInTenant(t, ctx, home)
	raw := rememberDevice(t, ctx, svc, userID, home, uaChromeMac)
	if svc.IsTrustedDevice(ctx, userID, other, raw) {
		t.Fatal("trust earned in one organisation must not skip the second factor in another")
	}
	if !svc.IsTrustedDevice(ctx, userID, home, raw) {
		t.Fatal("the device must stay trusted where it was remembered")
	}
}

// TestRememberedForTheOrganisationsDays: a device is remembered for the
// organisation's remember_device_days.
func TestRememberedForTheOrganisationsDays(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("devices-days"))
	userID := createUserInTenant(t, ctx, tenantID)
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, remember_device_enabled, remember_device_days) VALUES ($1, TRUE, 7)`,
		tenantID); err != nil {
		t.Fatal(err)
	}
	raw, ttl, err := svc.MaybeRememberDevice(ctx, userID, tenantID, uaChromeMac)
	if err != nil || raw == "" || ttl != 7*24*time.Hour {
		t.Fatalf("remember: %v (raw set %v, ttl %v), want 7 days", err, raw != "", ttl)
	}
	list, _ := svc.ListTrustedDevices(ctx, userID, &tenantID, "")
	if len(list) != 1 || time.Until(list[0].ExpiresAt) > 7*24*time.Hour || time.Until(list[0].ExpiresAt) < 6*24*time.Hour {
		t.Fatalf("expires %v, want seven days out", list)
	}
}

// TestPasswordAndResetForgetTrustedDevices: a changed password, and an
// administrator resetting the person's factors, forget every remembered device.
func TestPasswordAndResetForgetTrustedDevices(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("devices-clear"))
	userID := createUserInTenant(t, ctx, tenantID)
	if _, err := testPool.Exec(ctx,
		`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, 'old-hash')`, userID); err != nil {
		t.Fatal(err)
	}
	rememberDevice(t, ctx, svc, userID, tenantID, uaChromeMac)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.password_credentials SET password_hash = 'new-hash' WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.ListTrustedDevices(ctx, userID, nil, ""); len(list) != 0 {
		t.Fatalf("a changed password must forget every device, %d left", len(list))
	}

	rememberDevice(t, ctx, svc, userID, tenantID, uaChromeMac)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newStepUpMFA(t).ResetForUser(ctx, tx, userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.ListTrustedDevices(ctx, userID, nil, ""); len(list) != 0 {
		t.Fatalf("a factor reset must forget every device, %d left", len(list))
	}
}

// TestAdministratorManagesMembersDevices: an administrator sees and forgets a
// member's devices remembered in their own organisation only, and gets 404 for
// someone who is not a member.
func TestAdministratorManagesMembersDevices(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	org, elsewhere := createTenant(t, ctx, uniqueSlug("devices-admin")), createTenant(t, ctx, uniqueSlug("devices-elsewhere"))
	admin, member := createUserInTenant(t, ctx, org), createUserInTenant(t, ctx, org)
	addTenantMembership(t, ctx, member, elsewhere)
	outsider := createUserInTenant(t, ctx, elsewhere)
	rememberDevice(t, ctx, svc, member, org, uaChromeMac)
	kept := rememberDevice(t, ctx, svc, member, elsewhere, uaIPhone)

	r := chi.NewRouter()
	r.Use(withPrincipal(admin, org))
	(&auth.Handler{Service: svc}).MountAuthed(r)
	call := func(method, path string) (int, []byte) {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, nil))
		return rr.Code, rr.Body.Bytes()
	}

	code, body := call(http.MethodGet, "/users/"+member.String()+"/trusted-devices")
	var got struct {
		Items []auth.TrustedDevice `json:"items"`
	}
	_ = json.Unmarshal(body, &got)
	if code != http.StatusOK || len(got.Items) != 1 || got.Items[0].TenantID == nil || *got.Items[0].TenantID != org {
		t.Fatalf("an administrator must see only devices remembered in their organisation: %d %s", code, body)
	}
	if code, _ := call(http.MethodGet, "/users/"+outsider.String()+"/trusted-devices"); code != http.StatusNotFound {
		t.Fatalf("someone who is not a member = %d, want 404", code)
	}
	if code, body := call(http.MethodDelete, "/users/"+member.String()+"/trusted-devices"); code != http.StatusOK {
		t.Fatalf("forget a member's devices: %d %s", code, body)
	}
	if !svc.IsTrustedDevice(ctx, member, elsewhere, kept) {
		t.Fatal("a device remembered in another organisation must be left alone")
	}
	if deviceAuditCount(t, ctx, admin, "auth.trusted_device_revoked") != 1 {
		t.Error("the administrator's forgetting must be audited with them as the actor")
	}
}

// TestExpiredTrustedDevicesAreCleanedUp: the session clean-up also removes
// remembered devices that expired before its cutoff.
func TestExpiredTrustedDevicesAreCleanedUp(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newDeviceAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("devices-expired"))
	userID := createUserInTenant(t, ctx, tenantID)
	rememberDevice(t, ctx, svc, userID, tenantID, uaChromeMac)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.trusted_devices SET expires_at = NOW() - INTERVAL '8 days' WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	purged, err := auth.PurgeEndedSessions(ctx, testPool, auth.SessionRetention, nil)
	if err != nil || purged.TrustedDevices < 1 {
		t.Fatalf("clean-up: %v (%d devices)", err, purged.TrustedDevices)
	}
}
