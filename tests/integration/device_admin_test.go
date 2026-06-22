//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id/domains/federation/oidc"
)

// TestDeviceAdminListAndRevoke proves the admin device-visibility surface: a
// created device authorization shows up in the tenant list (with no device_code
// leaked), and revoking it flips the status to denied so a subsequent token
// poll fails with access_denied.
func TestDeviceAdminListAndRevoke(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("devadm"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	deviceCode, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}

	// List: the row appears, scoped to the tenant.
	devices, err := svc.ListDevices(ctx, tenantID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	var found *oidc.DeviceAuthorization
	for i := range devices {
		if devices[i].UserCode == userCode {
			found = &devices[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("device %q not in tenant list", userCode)
	}
	if found.ClientID != client.ClientID {
		t.Errorf("device client_id = %q, want %q", found.ClientID, client.ClientID)
	}
	if found.Status != "pending" {
		t.Errorf("device status = %q, want pending", found.Status)
	}

	// The device_code (and its hash) must never appear in the JSON-facing view.
	// DeviceAuthorization has no device_code field; assert the raw value isn't
	// echoed in any string field as a belt-and-braces check.
	for _, s := range []string{found.UserCode, found.UserEmail, found.ClientID} {
		if strings.Contains(s, deviceCode) {
			t.Fatalf("device_code leaked into admin view field %q", s)
		}
	}

	// A foreign tenant does not see this device.
	otherTenant := createTenant(t, ctx, uniqueSlug("devadm2"))
	otherDevices, err := svc.ListDevices(ctx, otherTenant)
	if err != nil {
		t.Fatalf("list other devices: %v", err)
	}
	for _, d := range otherDevices {
		if d.UserCode == userCode {
			t.Fatal("device leaked across tenants in the admin list")
		}
	}

	// Revoke: flips status to denied; tenant-scoped.
	tx := beginTx(t, ctx)
	gotClientID, gotUserCode, err := svc.RevokeDevice(ctx, tx, tenantID, found.ID)
	if err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	commitTx(t, ctx, tx)
	if gotClientID != client.ClientID || gotUserCode != userCode {
		t.Errorf("revoke returned (%q,%q), want (%q,%q)", gotClientID, gotUserCode, client.ClientID, userCode)
	}

	// Status is now denied.
	var status string
	if err := testPool.QueryRow(ctx,
		`SELECT status FROM auth.oidc_device_codes WHERE id = $1`, found.ID).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "denied" {
		t.Errorf("status after revoke = %q, want denied", status)
	}

	// A subsequent token poll fails (access_denied for a denied row).
	resetPollClock(t, ctx, userCode)
	if _, err := svc.DeviceToken(ctx, client.ClientID, deviceCode); err == nil ||
		!strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("poll after revoke = %v, want access_denied", err)
	}
}

// TestDeviceAdminRevokeCrossTenant proves a tenant cannot revoke another
// tenant's device authorization.
func TestDeviceAdminRevokeCrossTenant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("devA"))
	tenantB := createTenant(t, ctx, uniqueSlug("devB"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, _ := registerOIDCClient(t, ctx, svc, tenantA, "https://app.example/cb")

	_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}

	// Tenant B (foreign) tries to revoke A's device → ErrNotFound, row untouched.
	devices, err := svc.ListDevices(ctx, tenantA)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	tx := beginTx(t, ctx)
	if _, _, err := svc.RevokeDevice(ctx, tx, tenantB, devices[0].ID); err == nil {
		t.Error("tenant B must not revoke tenant A's device")
	}
	_ = tx.Rollback(ctx)

	var status string
	if err := testPool.QueryRow(ctx,
		`SELECT status FROM auth.oidc_device_codes WHERE user_code = $1`, userCode).Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "pending" {
		t.Errorf("status = %q after foreign revoke attempt, want pending", status)
	}
}
