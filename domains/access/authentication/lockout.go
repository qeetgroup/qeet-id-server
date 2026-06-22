package auth

import (
	"context"
	"log/slog"
	"time"
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
	var until *time.Time
	if err := s.pool.QueryRow(ctx,
		`SELECT locked_until FROM auth.login_attempts WHERE email = $1`, email,
	).Scan(&until); err != nil || until == nil {
		return time.Time{}, false
	}
	if time.Now().Before(*until) {
		return *until, true
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
	// In ON CONFLICT DO UPDATE the existing row is referenced by the bare
	// relation name (login_attempts), not the schema-qualified form. RETURNING
	// the new counter lets us fire an anomaly exactly once, on the attempt that
	// crosses the lockout threshold (not on every subsequent locked attempt).
	var failedCount int
	err := s.pool.QueryRow(ctx, `
		INSERT INTO auth.login_attempts (email, failed_count, first_failed_at, last_failed_at)
		VALUES ($1, 1, NOW(), NOW())
		ON CONFLICT (email) DO UPDATE SET
			failed_count = CASE
				WHEN login_attempts.last_failed_at < $2 THEN 1
				ELSE login_attempts.failed_count + 1 END,
			first_failed_at = CASE
				WHEN login_attempts.last_failed_at < $2 THEN NOW()
				ELSE login_attempts.first_failed_at END,
			last_failed_at = NOW(),
			locked_until = CASE
				WHEN (CASE
					WHEN login_attempts.last_failed_at < $2 THEN 1
					ELSE login_attempts.failed_count + 1 END) >= $3
				THEN $4::timestamptz ELSE NULL END
		RETURNING failed_count
	`, email, windowStart, maxFailedLogins, lockUntil).Scan(&failedCount)
	if err != nil {
		slog.Warn("record failed login", "err", err)
		return
	}
	// Exactly at the threshold = the attempt that just locked the account.
	if failedCount == maxFailedLogins && s.anomaly != nil {
		s.anomaly.OnAccountLocked(ctx, email)
	}
}

// clearLoginAttempts resets the counter after a successful login.
func (s *Service) clearLoginAttempts(ctx context.Context, email string) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM auth.login_attempts WHERE email = $1`, email)
}
