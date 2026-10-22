package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/useragent"
)

// TrustedDeviceCookie marks a browser the user has completed MFA from before.
// Adaptive MFA (when the tenant opts in) lets such a device skip the second
// factor for trustedDeviceTTL. HttpOnly + only the hash is stored, like the SSO
// session and refresh tokens.
const TrustedDeviceCookie = "qe_td"

// trustedDeviceTTL is how long a device stays trusted where the organisation
// sets nothing (tenant.auth_policy.remember_device_days, 30 by default).
const trustedDeviceTTL = 30 * 24 * time.Hour

// CreateTrustedDevice mints a trusted-device token for a user in tenantID that
// stays trusted for ttl, stores its hash and audits it, returning the raw
// cookie value. Only called after a successful MFA completion, so trust always
// follows a real second-factor verification.
func (s *Service) CreateTrustedDevice(ctx context.Context, userID, tenantID uuid.UUID, label string, ttl time.Duration) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var tid any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		tid = tenantID
		tenantPtr = &tenantID
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	expires := time.Now().UTC().Add(ttl)
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, label, expires_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING id
	`, userID, tid, hash, label, expires).Scan(&id); err != nil {
		return "", err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: tenantPtr, ActorUserID: &userID, ActorType: "user",
		Action: "auth.trusted_device_added", ResourceType: "trusted_device", ResourceID: &id,
		UserAgent: label, Metadata: map[string]any{"expires_at": expires},
	}); err != nil {
		return "", err
	}
	return raw, tx.Commit(ctx)
}

// IsTrustedDevice reports whether raw is a live trusted-device token for userID
// in tenantID, and records its use. Trust from one organisation never applies in
// another.
func (s *Service) IsTrustedDevice(ctx context.Context, userID, tenantID uuid.UUID, raw string) bool {
	if raw == "" || tenantID == uuid.Nil {
		return false
	}
	id, err := s.q.TouchTrustedDevice(ctx, dbgen.TouchTrustedDeviceParams{
		TokenHash: tokens.HashRefresh(raw),
		UserID:    userID,
		TenantID:  pgtype.UUID{Bytes: tenantID, Valid: true},
	})
	if err != nil {
		return false
	}
	if tx, err := s.pool.Begin(ctx); err == nil {
		defer tx.Rollback(ctx)
		if audit.Record(ctx, tx, audit.Event{
			TenantID: &tenantID, ActorUserID: &userID, ActorType: "user",
			Action: "auth.trusted_device_used", ResourceType: "trusted_device", ResourceID: &id,
		}) == nil {
			_ = tx.Commit(ctx)
		}
	}
	return true
}

// MaybeRememberDevice creates a trusted device when the tenant has adaptive MFA
// on, and returns the cookie value and its lifetime. It returns "" when the
// tenant doesn't remember devices, whatever the client asked for.
func (s *Service) MaybeRememberDevice(ctx context.Context, userID, tenantID uuid.UUID, label string) (string, time.Duration, error) {
	if s.devicePolicy == nil || tenantID == uuid.Nil {
		return "", 0, nil
	}
	ok, ttl, err := s.devicePolicy.RememberDevicePolicy(ctx, tenantID)
	if err != nil || !ok {
		return "", 0, err
	}
	if ttl <= 0 {
		ttl = trustedDeviceTTL
	}
	raw, err := s.CreateTrustedDevice(ctx, userID, tenantID, label, ttl)
	return raw, ttl, err
}

// SetTrustedDeviceCookie writes the long-lived HttpOnly trusted-device cookie,
// kept for as long as the device stays trusted.
func SetTrustedDeviceCookie(w http.ResponseWriter, raw string, maxAge time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     TrustedDeviceCookie,
		Value:    raw,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
}

// TrustedDevice is a remembered device as its owner or an administrator sees
// it: named from the browser that was remembered ("Chrome on macOS"), with
// when it was remembered, last skipped the second factor, and stops being
// remembered.
type TrustedDevice struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   *uuid.UUID `json:"tenant_id"`
	Device     string     `json:"device"`
	DeviceKind string     `json:"device_kind"`
	UserAgent  string     `json:"user_agent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	// Current: this is the device the request came from.
	Current bool `json:"current"`
}

// ListTrustedDevices lists userID's live remembered devices, newest first: in
// every organisation when tenantID is nil (the person's own view), else only
// those remembered in it (an administrator's view). currentRaw is the
// request's own trusted-device cookie, to mark it.
func (s *Service) ListTrustedDevices(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, currentRaw string) ([]TrustedDevice, error) {
	current := ""
	if currentRaw != "" {
		current = tokens.HashRefresh(currentRaw)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, label, created_at, last_used_at, expires_at, token_hash = $3
		FROM auth.trusted_devices
		WHERE user_id = $1 AND ($2::uuid IS NULL OR tenant_id = $2) AND expires_at > NOW()
		ORDER BY created_at DESC, id
	`, userID, tenantID, current)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (TrustedDevice, error) {
		var d TrustedDevice
		err := row.Scan(&d.ID, &d.TenantID, &d.UserAgent, &d.CreatedAt, &d.LastUsedAt, &d.ExpiresAt, &d.Current)
		device := useragent.Parse(d.UserAgent)
		d.Device, d.DeviceKind = device.Label(), device.Kind
		return d, err
	})
}

// ForgetTrustedDevicesInput says whose remembered devices to forget and who
// asks. TenantID nil: in every organisation (the person themselves); else only
// those remembered in it (an administrator). DeviceID nil: all of them.
type ForgetTrustedDevicesInput struct {
	UserID   uuid.UUID
	TenantID *uuid.UUID
	DeviceID *uuid.UUID
	Actor    audit.Actor
}

// ForgetTrustedDevices forgets remembered devices, so each is asked for the
// second factor at its next sign-in, and audits each one forgotten. Forgetting
// one that does not exist (or is not in scope) is ErrNotFound.
func (s *Service) ForgetTrustedDevices(ctx context.Context, in ForgetTrustedDevicesInput) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		DELETE FROM auth.trusted_devices
		WHERE user_id = $1 AND ($2::uuid IS NULL OR tenant_id = $2) AND ($3::uuid IS NULL OR id = $3)
		RETURNING id, tenant_id
	`, in.UserID, in.TenantID, in.DeviceID)
	if err != nil {
		return 0, err
	}
	type forgotten struct {
		id       uuid.UUID
		tenantID *uuid.UUID
	}
	gone, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (forgotten, error) {
		var f forgotten
		return f, row.Scan(&f.id, &f.tenantID)
	})
	if err != nil {
		return 0, err
	}
	if in.DeviceID != nil && len(gone) == 0 {
		return 0, errs.ErrNotFound
	}
	for _, f := range gone {
		tenant := f.tenantID
		if in.TenantID != nil {
			tenant = in.TenantID
		}
		ev := in.Actor.PlatformEvent("auth.trusted_device_revoked", "trusted_device", f.id,
			map[string]any{"user_id": in.UserID})
		ev.TenantID = tenant
		if err := audit.Record(ctx, tx, ev); err != nil {
			return 0, err
		}
	}
	return int64(len(gone)), tx.Commit(ctx)
}

// TrustedDeviceSummary is the tenant's live trusted-device estate.
type TrustedDeviceSummary struct {
	// Devices counts rows: one browser cookie is one device, so a person with a
	// laptop and a phone contributes two.
	Devices int `json:"devices"`
	// Users is how many distinct people those devices belong to, so the console
	// can say "N devices across M people" without a second round trip.
	Users int `json:"users"`
}

// CountTrustedDevices returns how many live (unexpired) trusted devices a tenant
// has. Each row is one device, so a person with two devices counts twice.
func (s *Service) CountTrustedDevices(
	ctx context.Context, tenantID uuid.UUID,
) (TrustedDeviceSummary, error) {
	var out TrustedDeviceSummary
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(DISTINCT user_id)
		FROM auth.trusted_devices
		WHERE tenant_id = $1 AND expires_at > NOW()
	`, tenantID).Scan(&out.Devices, &out.Users)
	return out, err
}

// IsMember reports whether userID belongs to tenantID: holds a role in it, or
// has it as their home organisation.
func (s *Service) IsMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	member, err := s.q.CheckTenantMembership(ctx, dbgen.CheckTenantMembershipParams{UserID: userID, TenantID: tenantID})
	if err != nil || member {
		return member, err
	}
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM "user".users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL)
	`, userID, tenantID).Scan(&member)
	return member, err
}
