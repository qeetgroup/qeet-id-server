//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// insertTrustedDevice writes a row directly: CreateTrustedDevice always uses the
// production TTL, and these cases need control over expiry and tenant.
func insertTrustedDevice(
	t *testing.T, ctx context.Context, userID uuid.UUID, tenantID any, expiresAt time.Time,
) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, label, expires_at)
		VALUES ($1, $2, $3, 'test device', $4)
	`, userID, tenantID, uuid.NewString(), expiresAt); err != nil {
		t.Fatalf("insert trusted device: %v", err)
	}
}

// The Authentication overview shows this as "registered devices", so it must
// count devices that are actually still trusted — and only this tenant's.
func TestCountTrustedDevices(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	mine := createTenant(t, ctx, uniqueSlug("tdmine"))
	theirs := createTenant(t, ctx, uniqueSlug("tdtheirs"))
	svc, _ := newAuth()

	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-1 * time.Hour)

	mineUser := createTenantUser(t, ctx, mine, uniqueSlug("td")+"@example.com")
	theirsUser := createTenantUser(t, ctx, theirs, uniqueSlug("td")+"@example.com")

	// Two live devices for one user — a laptop and a phone both count.
	insertTrustedDevice(t, ctx, mineUser, mine, future)
	insertTrustedDevice(t, ctx, mineUser, mine, future)
	// Expired: no longer trusted, MFA is asked for again, must not be counted.
	insertTrustedDevice(t, ctx, mineUser, mine, past)
	// Another tenant's device.
	insertTrustedDevice(t, ctx, theirsUser, theirs, future)
	// Tenant-less session (tenant_id is nullable and written NULL for those).
	insertTrustedDevice(t, ctx, mineUser, nil, future)

	got, err := svc.CountTrustedDevices(ctx, mine)
	if err != nil {
		t.Fatalf("CountTrustedDevices: %v", err)
	}
	if got.Devices != 2 {
		t.Errorf("devices = %d, want 2 (live + this tenant only)", got.Devices)
	}
	// Both live devices belong to the same person, so the people count is 1 —
	// the card says "N devices across M people" and must not conflate them.
	if got.Users != 1 {
		t.Errorf("users = %d, want 1", got.Users)
	}

	other, err := svc.CountTrustedDevices(ctx, theirs)
	if err != nil {
		t.Fatalf("CountTrustedDevices(theirs): %v", err)
	}
	if other.Devices != 1 || other.Users != 1 {
		t.Errorf("other tenant = %+v, want 1 device / 1 user", other)
	}
}

// A tenant that has never enabled adaptive MFA has no rows at all — the card
// legitimately reads zero rather than erroring.
func TestCountTrustedDevicesEmptyTenant(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("tdempty"))

	svc, _ := newAuth()
	got, err := svc.CountTrustedDevices(ctx, tid)
	if err != nil {
		t.Fatalf("CountTrustedDevices: %v", err)
	}
	if got.Devices != 0 || got.Users != 0 {
		t.Errorf("empty tenant = %+v, want zeroes", got)
	}
}
