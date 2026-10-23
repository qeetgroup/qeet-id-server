package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

// A session ends at its expires_at (the organisation's maximum session age) or
// after idle_timeout without renewal. Both are checked at renewal, so an issued
// access token lasts at most its own short lifetime beyond the end.

// The bounds of a session whose organisation sets none, or that has no
// organisation, until SetSessionLifetime is called — the defaults of
// SESSION_MAX_AGE and SESSION_IDLE_TIMEOUT.
const (
	defaultSessionMaxAge      = 30 * 24 * time.Hour
	defaultSessionIdleTimeout = 24 * time.Hour
)

// SetSessionLifetime sets the bounds of a session whose organisation's security
// policy sets none, or that has no organisation.
func (s *Service) SetSessionLifetime(maxAge, idle time.Duration) {
	s.sessionMaxAge, s.sessionIdle = maxAge, idle
}

func (s *Service) sessionDefaults() (maxAge, idle time.Duration) {
	maxAge, idle = s.sessionMaxAge, s.sessionIdle
	if maxAge <= 0 {
		maxAge = defaultSessionMaxAge
	}
	if idle <= 0 {
		idle = defaultSessionIdleTimeout
	}
	return maxAge, idle
}

// Why a session timed out, as recorded and announced.
const (
	timedOutMaxAge = "max_age"
	timedOutIdle   = "idle"
)

// endTimedOutSession ends a session found past one of its bounds: it is marked
// ended now, which is after the bound, so it still reads as expired rather
// than revoked; subscribers are told it expired, and the audit record says
// which bound it reached.
func (s *Service) endTimedOutSession(ctx context.Context, tx pgx.Tx, userID, tenantID, sessionID uuid.UUID, reason string, in RefreshInput) error {
	if err := s.q.WithTx(tx).RevokeSessionById(ctx, sessionID); err != nil {
		return err
	}
	s.signals.Revoked(ctx, tx, sessionsignal.ReasonExpired,
		sessionsignal.Session{ID: sessionID, UserID: userID, TenantID: tenantID})
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		tenantPtr = &tenantID
	}
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "system",
		Action:       "auth.session_expired",
		ResourceType: "session",
		ResourceID:   &sessionID,
		IP:           in.IP,
		UserAgent:    in.UserAgent,
		RequestID:    in.RequestID,
		Metadata:     map[string]any{"session_id": sessionID, "reason": reason},
	})
}
