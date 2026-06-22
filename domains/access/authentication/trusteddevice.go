package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/tokens"
)

// TrustedDeviceCookie marks a browser the user has completed MFA from before.
// Adaptive MFA (when the tenant opts in) lets such a device skip the second
// factor for trustedDeviceTTL. HttpOnly + only the hash is stored, like the SSO
// session and refresh tokens.
const TrustedDeviceCookie = "qe_td"

// trustedDeviceTTL bounds how long a device stays trusted before MFA is asked
// again.
const trustedDeviceTTL = 30 * 24 * time.Hour

// CreateTrustedDevice mints a trusted-device token for a user and stores its
// hash, returning the raw cookie value. Only called after a successful MFA
// completion, so trust always follows a real second-factor verification.
func (s *Service) CreateTrustedDevice(ctx context.Context, userID, tenantID uuid.UUID, label string) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var tid any
	if tenantID != uuid.Nil {
		tid = tenantID
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, label, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, tid, hash, label, time.Now().UTC().Add(trustedDeviceTTL)); err != nil {
		return "", err
	}
	return raw, nil
}

// IsTrustedDevice reports whether raw is a live trusted-device token bound to
// userID, refreshing last_used_at on a hit. The user_id is part of the WHERE
// clause, so a token issued to a different account can never match — a stolen
// or replayed cookie can't be used to skip MFA for someone else.
func (s *Service) IsTrustedDevice(ctx context.Context, userID uuid.UUID, raw string) bool {
	if raw == "" {
		return false
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE auth.trusted_devices SET last_used_at = NOW()
		WHERE token_hash = $1 AND user_id = $2 AND expires_at > NOW()
	`, tokens.HashRefresh(raw), userID)
	if err != nil {
		return false
	}
	return ct.RowsAffected() > 0
}

// MaybeRememberDevice mints a trusted device only when the tenant has opted into
// adaptive MFA. Returns the raw cookie value to set, or "" when remembering is
// off (so the HTTP layer never trusts a client-supplied "remember" flag the
// policy doesn't allow).
func (s *Service) MaybeRememberDevice(ctx context.Context, userID, tenantID uuid.UUID, label string) (string, error) {
	if s.devicePolicy == nil || tenantID == uuid.Nil {
		return "", nil
	}
	ok, err := s.devicePolicy.RememberDeviceEnabled(ctx, tenantID)
	if err != nil || !ok {
		return "", err
	}
	return s.CreateTrustedDevice(ctx, userID, tenantID, label)
}

// SetTrustedDeviceCookie writes the long-lived HttpOnly trusted-device cookie.
func SetTrustedDeviceCookie(w http.ResponseWriter, raw string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     TrustedDeviceCookie,
		Value:    raw,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(trustedDeviceTTL.Seconds()),
	})
}
