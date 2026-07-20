package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/domains/access/authentication/dbgen"
)

// Brute-force lockout policy. After maxFailedLogins consecutive failed logins
// within failureWindow, the account is locked for lockoutDuration. The counter
// resets on a successful login, or once failureWindow elapses with no new
// failure. Keyed by lowercased email, so probing for valid accounts is
// throttled identically to wrong-password attempts on real ones.
const (
	maxFailedLogins = 5
	failureWindow   = 15 * time.Minute
	lockoutDuration = 15 * time.Minute
)

// loginLockedUntil reports the lock expiry for an email if it is currently
// locked. A storage error returns "not locked" — the lockout is a throttle, not
// the authentication decision, so a DB blip must never block a valid login.
func (s *Service) loginLockedUntil(ctx context.Context, email string) (time.Time, bool) {
	row, err := s.q.GetLoginAttempt(ctx, email)
	// pgx.ErrNoRows = no prior attempts; any other error = DB blip → both safe.
	if errors.Is(err, pgx.ErrNoRows) || err != nil || !row.Valid {
		return time.Time{}, false
	}
	if time.Now().Before(row.Time) {
		return row.Time, true
	}
	return time.Time{}, false
}

// recordFailedLogin increments the failure counter for an email and sets the
// lock once the threshold is crossed. A counter older than failureWindow
// restarts from one. Best-effort: a storage error is swallowed (it can only
// weaken throttling, never grant access).
func (s *Service) recordFailedLogin(ctx context.Context, email string) {
	now := time.Now()
	windowStart := now.Add(-failureWindow)
	lockUntil := now.Add(lockoutDuration)
	// RETURNING the new counter lets us fire an anomaly exactly once, on the
	// attempt that crosses the lockout threshold (not on every subsequent one).
	failedCount, err := s.q.UpsertLoginAttempt(ctx, dbgen.UpsertLoginAttemptParams{
		Email:           email,
		WindowStart:     windowStart,
		MaxFailedLogins: int32(maxFailedLogins),
		LockUntil:       lockUntil,
	})
	if err != nil {
		slog.Warn("record failed login", "err", err)
		return
	}
	// Exactly at the threshold = the attempt that just locked the account.
	if int(failedCount) == maxFailedLogins && s.anomaly != nil {
		s.anomaly.OnAccountLocked(ctx, email)
	}
}

// clearLoginAttempts resets the counter after a successful login.
func (s *Service) clearLoginAttempts(ctx context.Context, email string) {
	_ = s.q.DeleteLoginAttempt(ctx, email)
}
