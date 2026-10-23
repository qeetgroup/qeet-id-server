package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	maxMFAAttempts   = 5
	mfaAttemptWindow = 10 * time.Minute

	// Budget purposes. Each is an independent counter so a burst against one
	// factor type can't lock a user out of the others.
	PurposeTOTPEnroll   = "totp-enroll"
	PurposeFactorVerify = "factor-verify"
	PurposeOTPVerify    = "otp-verify"
)

// PurposeOTPEnroll scopes the budget to the factor being confirmed, so
// enrolling a second phone isn't blocked by a fumbled first one.
func PurposeOTPEnroll(factorID uuid.UUID) string { return "otp-enroll:" + factorID.String() }

// Attempt is one reserved verification slot. ReserveAttempt commits it in its
// own transaction so the count survives a rejected code's rollback. Callers
// must reserve before opening the transaction they verify in and refund only
// after it ends; otherwise each verification holds two pool connections.
type Attempt struct {
	userID    uuid.UUID
	purpose   string
	remaining int
}

// ReserveAttempt atomically claims one verification attempt. The fifth slot is
// allowed to proceed but locks subsequent attempts unless it succeeds and
// clears the budget.
func (s *Service) ReserveAttempt(ctx context.Context, userID uuid.UUID, purpose string) (Attempt, error) {
	claim := Attempt{userID: userID, purpose: purpose}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return claim, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.mfa_attempt_budgets (user_id, purpose)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, userID, purpose); err != nil {
		return claim, err
	}
	var failed int16
	var windowStarted time.Time
	var lockedUntil pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT failed_attempts, window_started_at, locked_until
		FROM auth.mfa_attempt_budgets
		WHERE user_id = $1 AND purpose = $2
		FOR UPDATE
	`, userID, purpose).Scan(&failed, &windowStarted, &lockedUntil); err != nil {
		return claim, err
	}
	now := time.Now().UTC()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		if err := tx.Commit(ctx); err != nil {
			return claim, err
		}
		return claim, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaAttemptWindow || (lockedUntil.Valid && !now.Before(lockedUntil.Time)) {
		failed = 0
		windowStarted = now
	}
	if failed >= maxMFAAttempts {
		if err := tx.Commit(ctx); err != nil {
			return claim, err
		}
		return claim, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	next := failed + 1
	var lock any
	if next >= maxMFAAttempts {
		lock = now.Add(mfaAttemptWindow)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET failed_attempts = $3, window_started_at = $4, locked_until = $5
		WHERE user_id = $1 AND purpose = $2
	`, userID, purpose, next, windowStarted, lock); err != nil {
		return claim, err
	}
	if err := tx.Commit(ctx); err != nil {
		return claim, err
	}
	claim.remaining = maxMFAAttempts - int(next)
	return claim, nil
}

// clearMFAAttempt drops the budget after a successful verification. It runs in
// the caller's transaction so the reset commits with the mutation it belongs to.
func clearMFAAttempt(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose string) error {
	_, err := tx.Exec(ctx, `DELETE FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = $2`, userID, purpose)
	return err
}

// RefundAttempt hands back a slot consumed by an infrastructure failure rather
// than a rejected credential. It takes its own connection, so callers must run
// it only once their own transaction is finished — see Attempt.
func (s *Service) RefundAttempt(ctx context.Context, claim Attempt) {
	if claim.purpose == "" {
		return
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET failed_attempts = GREATEST(failed_attempts - 1, 0), locked_until = NULL
		WHERE user_id = $1 AND purpose = $2
	`, claim.userID, claim.purpose)
}

// refundable reports whether err is an infrastructure failure rather than a
// rejected credential, and so should not cost the user an attempt. Budget
// exhaustion is never refundable: the slot was already spent when it was
// counted, and refunding would let a caller retry past the lock.
func refundable(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, errs.ErrMFAAttemptsExceeded),
		errors.Is(err, errs.ErrMFACodeInvalid),
		errors.Is(err, errs.ErrMFATOTPCodeInvalid),
		errors.Is(err, errs.ErrMFAOTPCodeInvalid):
		return false
	}
	return true
}

// refund hands a reserved slot back when the request failed for an
// infrastructure reason rather than a rejected credential. Handlers defer it
// *before* opening their transaction, so it runs once that transaction has
// closed and never needs a second connection alongside it.
func (h *Handler) refund(ctx context.Context, attempt Attempt, err error) {
	if refundable(err) {
		h.Service.RefundAttempt(ctx, attempt)
	}
}

// attemptError attaches the caller's remaining budget to a rejection so
// clients can render "2 attempts left" from data rather than message text.
func attemptError(base *errs.Error, remaining int) error {
	if remaining == 0 {
		return errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	return base.WithMetadata(map[string]any{"remaining_attempts": remaining})
}

// OTPCodeRetention is how long an email or SMS code is kept after it expires,
// so the hourly sending limits still see every code sent in the last hour.
const OTPCodeRetention = 24 * time.Hour

// PurgeExpiredPushChallenges deletes push approval requests that expired
// longer ago than retention, answered or not, and returns how many. Run on a
// schedule.
func PurgeExpiredPushChallenges(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM auth.mfa_push_challenges WHERE expires_at < $1`,
		time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// PurgeExpiredOTPCodes deletes the email and SMS codes that expired longer ago
// than retention, used or not, and returns how many. Run on a schedule.
func PurgeExpiredOTPCodes(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	tag, err := pool.Exec(ctx, `DELETE FROM auth.mfa_otp_codes WHERE expires_at < $1`, time.Now().UTC().Add(-retention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
