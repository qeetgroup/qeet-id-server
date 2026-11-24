package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
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

// Attempt is one reserved verification slot. reserveAttempt commits it in its
// own transaction so the count survives a rejected code's rollback. A flow
// reserves before opening the transaction it verifies in and refunds only
// after it ends; otherwise each verification holds two pool connections.
type Attempt struct {
	userID    uuid.UUID
	purpose   string
	remaining int
}

// reserveAttempt atomically claims one verification attempt. The fifth slot is
// allowed to proceed but locks subsequent attempts unless it succeeds and
// clears the budget.
func (s *Service) reserveAttempt(ctx context.Context, userID uuid.UUID, purpose string) (Attempt, error) {
	claim := Attempt{userID: userID, purpose: purpose}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return claim, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if err := q.EnsureAttemptBudget(ctx, dbgen.EnsureAttemptBudgetParams{UserID: userID, Purpose: purpose}); err != nil {
		return claim, err
	}
	budget, err := q.LockAttemptBudget(ctx, dbgen.LockAttemptBudgetParams{UserID: userID, Purpose: purpose})
	if err != nil {
		return claim, err
	}
	failed, windowStarted, lockedUntil := budget.FailedAttempts, budget.WindowStartedAt, budget.LockedUntil
	now := time.Now().UTC()
	if lockedUntil != nil && now.Before(*lockedUntil) {
		if err := tx.Commit(ctx); err != nil {
			return claim, err
		}
		return claim, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaAttemptWindow || (lockedUntil != nil && !now.Before(*lockedUntil)) {
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
	var lock *time.Time
	if next >= maxMFAAttempts {
		lock = new(now.Add(mfaAttemptWindow))
	}
	if err := q.SetAttemptBudget(ctx, dbgen.SetAttemptBudgetParams{
		UserID: userID, Purpose: purpose, FailedAttempts: next, WindowStartedAt: windowStarted, LockedUntil: lock,
	}); err != nil {
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
	return dbgen.New(tx).ClearAttemptBudget(ctx, dbgen.ClearAttemptBudgetParams{UserID: userID, Purpose: purpose})
}

// refund hands back a slot err did not spend: one consumed by an
// infrastructure failure rather than a rejected credential. It takes its own
// connection, so a flow runs it only once its transaction is finished — see
// Attempt.
func (s *Service) refund(ctx context.Context, claim Attempt, err error) {
	if claim.purpose == "" || !refundable(err) {
		return
	}
	_ = s.q.RefundAttempt(ctx, dbgen.RefundAttemptParams{UserID: claim.userID, Purpose: claim.purpose})
}

// withAttempt reserves an attempt of userID's for purpose and runs verify with
// it, handing the attempt back when verify fails for an infrastructure reason.
func (s *Service) withAttempt(ctx context.Context, userID uuid.UUID, purpose string, verify func(Attempt) error) error {
	attempt, err := s.reserveAttempt(ctx, userID, purpose)
	if err != nil {
		return err
	}
	err = verify(attempt)
	s.refund(ctx, attempt, err)
	return err
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
		errors.Is(err, ErrTOTPCodeInvalid),
		errors.Is(err, ErrOTPCodeInvalid):
		return false
	}
	return true
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
	q, cutoff := dbgen.New(pool), time.Now().UTC().Add(-retention)
	return postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.PurgeExpiredPushChallenges(ctx, dbgen.PurgeExpiredPushChallengesParams{Cutoff: cutoff, MaxRows: limit})
	})
}

// PurgeExpiredOTPCodes deletes the email and SMS codes that expired longer ago
// than retention, used or not, and returns how many. Run on a schedule.
func PurgeExpiredOTPCodes(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	q, cutoff := dbgen.New(pool), time.Now().UTC().Add(-retention)
	return postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.PurgeExpiredOTPCodes(ctx, dbgen.PurgeExpiredOTPCodesParams{Cutoff: cutoff, MaxRows: limit})
	})
}
