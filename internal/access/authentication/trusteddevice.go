package authentication

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TrustedDeviceCookie marks a browser the user has completed MFA from before.
// Adaptive MFA (when the organization opts in) lets such a device skip the second
// factor for trustedDeviceTTL. HttpOnly + only the hash is stored, like the SSO
// session and refresh tokens.
const TrustedDeviceCookie = "qe_td"

// trustedDeviceTTL is how long a device stays trusted where the organization
// sets nothing (organization.auth_policy.remember_device_days, 30 by default).
const trustedDeviceTTL = 30 * 24 * time.Hour

// CreateTrustedDevice mints a trusted-device token for a user in organizationID that
// stays trusted for ttl, stores its hash and audits it, returning the raw
// cookie value. Only called after a successful MFA completion, so trust always
// follows a real second-factor verification.
func (s *Service) CreateTrustedDevice(ctx context.Context, userID, organizationID uuid.UUID, label string, ttl time.Duration) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	organizationPtr := orNil(organizationID)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	expires := time.Now().UTC().Add(ttl)
	id, err := s.q.WithTx(tx).InsertTrustedDevice(ctx, dbgen.InsertTrustedDeviceParams{
		UserID: userID, OrganizationID: organizationPtr, TokenHash: hash, Label: label, ExpiresAt: expires,
	})
	if err != nil {
		return "", err
	}
	// The device is named by the browser remembered, its user agent.
	if err := audit.Record(ctx, tx, asUser(userID, "", label).EventIn(organizationPtr, "auth.trusted_device_added", "trusted_device", id,
		map[string]any{"expires_at": expires})); err != nil {
		return "", err
	}
	return raw, tx.Commit(ctx)
}

// IsTrustedDevice reports whether raw is a live trusted-device token for userID
// in organizationID, and records its use. Trust from one organization never applies in
// another.
func (s *Service) IsTrustedDevice(ctx context.Context, userID, organizationID uuid.UUID, raw string) bool {
	if raw == "" || organizationID == uuid.Nil {
		return false
	}
	id, err := s.q.TouchTrustedDevice(ctx, dbgen.TouchTrustedDeviceParams{
		TokenHash:      tokens.HashRefresh(raw),
		UserID:         userID,
		OrganizationID: &organizationID,
	})
	if err != nil {
		return false
	}
	_ = audit.RecordAlone(ctx, s.pool, audit.Actor{UserID: &userID, Type: "user"}.Event(organizationID, "auth.trusted_device_used", "trusted_device", id, nil))
	return true
}

// MaybeRememberDevice creates a trusted device when the organization has adaptive MFA
// on, and returns the cookie value and its lifetime. It returns "" when the
// organization doesn't remember devices, whatever the client asked for.
func (s *Service) MaybeRememberDevice(ctx context.Context, userID, organizationID uuid.UUID, label string) (string, time.Duration, error) {
	if organizationID == uuid.Nil {
		return "", 0, nil
	}
	ok, ttl, err := s.devicePolicy.RememberDevicePolicy(ctx, organizationID)
	if err != nil || !ok {
		return "", 0, err
	}
	if ttl <= 0 {
		ttl = trustedDeviceTTL
	}
	raw, err := s.CreateTrustedDevice(ctx, userID, organizationID, label, ttl)
	return raw, ttl, err
}

// SetTrustedDeviceCookie writes the long-lived HttpOnly trusted-device cookie,
// kept for as long as the device stays trusted.
func SetTrustedDeviceCookie(w http.ResponseWriter, raw string, maxAge time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
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
	ID             uuid.UUID  `json:"id"`
	OrganizationID *uuid.UUID `json:"organization_id"`
	Device         string     `json:"device"`
	DeviceKind     string     `json:"device_kind"`
	UserAgent      string     `json:"user_agent"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	// Current: this is the device the request came from.
	Current bool `json:"current"`
}

// ListTrustedDevices lists userID's live remembered devices, newest first: in
// every organization when organizationID is nil (the person's own view), else only
// those remembered in it (an administrator's view). currentRaw is the
// request's own trusted-device cookie, to mark it.
func (s *Service) ListTrustedDevices(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, currentRaw string) ([]TrustedDevice, error) {
	current := ""
	if currentRaw != "" {
		current = tokens.HashRefresh(currentRaw)
	}
	rows, err := s.q.ListTrustedDevices(ctx, dbgen.ListTrustedDevicesParams{UserID: userID, OrganizationID: organizationID, CurrentHash: current})
	if err != nil {
		return nil, err
	}
	out := make([]TrustedDevice, len(rows))
	for i, row := range rows {
		device := httpx.Parse(row.Label)
		out[i] = TrustedDevice{ID: row.ID, OrganizationID: row.OrganizationID, Device: device.Label(), DeviceKind: device.Kind,
			UserAgent: row.Label, CreatedAt: row.CreatedAt, LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt, Current: row.Current}
	}
	return out, nil
}

// ForgetTrustedDevicesInput says whose remembered devices to forget and who
// asks. OrganizationID nil: in every organization (the person themselves); else only
// those remembered in it (an administrator). DeviceID nil: all of them.
type ForgetTrustedDevicesInput struct {
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	DeviceID       *uuid.UUID
	audit.Actor
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
	gone, err := s.q.WithTx(tx).ForgetTrustedDevices(ctx, dbgen.ForgetTrustedDevicesParams{
		UserID: in.UserID, OrganizationID: in.OrganizationID, DeviceID: in.DeviceID,
	})
	if err != nil {
		return 0, err
	}
	if in.DeviceID != nil && len(gone) == 0 {
		return 0, errs.ErrNotFound
	}
	for _, f := range gone {
		organization := f.OrganizationID
		if in.OrganizationID != nil {
			organization = in.OrganizationID
		}
		if err := audit.Record(ctx, tx, in.EventIn(organization, "auth.trusted_device_revoked", "trusted_device", f.ID,
			map[string]any{"user_id": in.UserID})); err != nil {
			return 0, err
		}
	}
	return int64(len(gone)), tx.Commit(ctx)
}

// TrustedDeviceSummary is the organization's live trusted-device estate.
type TrustedDeviceSummary struct {
	// Devices counts rows: one browser cookie is one device, so a person with a
	// laptop and a phone contributes two.
	Devices int `json:"devices"`
	// Users is how many distinct people those devices belong to, so the console
	// can say "N devices across M people" without a second round trip.
	Users int `json:"users"`
}

// CountTrustedDevices returns how many live (unexpired) trusted devices an organization
// has. Each row is one device, so a person with two devices counts twice.
func (s *Service) CountTrustedDevices(
	ctx context.Context, organizationID uuid.UUID,
) (TrustedDeviceSummary, error) {
	row, err := s.q.CountTrustedDevices(ctx, &organizationID)
	return TrustedDeviceSummary{Devices: int(row.Devices), Users: int(row.Users)}, err
}

// IsMember reports whether userID belongs to organizationID: holds a role in it, or
// has it as their home organization.
func (s *Service) IsMember(ctx context.Context, userID, organizationID uuid.UUID) (bool, error) {
	member, err := s.q.CheckOrganizationMembership(ctx, dbgen.CheckOrganizationMembershipParams{UserID: userID, OrganizationID: organizationID})
	if err != nil || member {
		return member, err
	}
	return s.q.IsHomeMember(ctx, dbgen.IsHomeMemberParams{UserID: userID, OrganizationID: &organizationID})
}
