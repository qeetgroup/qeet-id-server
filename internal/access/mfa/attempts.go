package mfa

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	maxMFAAttempts   = 5
	mfaAttemptWindow = 10 * time.Minute
)

// reserveMFAAttempt atomically claims one verification attempt. The fifth slot
// is allowed to proceed but locks subsequent attempts unless it succeeds and
// clears the budget.
func (s *Service) reserveMFAAttempt(ctx context.Context, userID uuid.UUID, purpose string) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.mfa_attempt_budgets (user_id, purpose)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`, userID, purpose); err != nil {
		return 0, err
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
		return 0, err
	}
	now := time.Now().UTC()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return 0, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaAttemptWindow || (lockedUntil.Valid && !now.Before(lockedUntil.Time)) {
		failed = 0
		windowStarted = now
	}
	if failed >= maxMFAAttempts {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return 0, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
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
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return maxMFAAttempts - int(next), nil
}

func clearMFAAttempt(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose string) error {
	_, err := tx.Exec(ctx, `DELETE FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = $2`, userID, purpose)
	return err
}

func (s *Service) releaseMFAAttempt(ctx context.Context, userID uuid.UUID, purpose string) {
	_, _ = s.pool.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET failed_attempts = GREATEST(failed_attempts - 1, 0), locked_until = NULL
		WHERE user_id = $1 AND purpose = $2
	`, userID, purpose)
}

func attemptError(base *errs.Error, remaining int) error {
	if remaining == 0 {
		return errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	return base.WithMetadata(map[string]any{"remaining_attempts": remaining})
}
