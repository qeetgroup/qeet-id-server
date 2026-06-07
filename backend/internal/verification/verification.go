// Package verification handles "send-a-code, prove-you-own-it" flows for
// email and phone. The Sender abstraction lets us swap SendGrid / Twilio
// at the boundary; tests use the LogSender.
package verification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/internal/platform/codes"
	"github.com/qeetgroup/qeet-id/internal/platform/errs"
	"github.com/qeetgroup/qeet-id/internal/platform/notifier"
)

type Service struct {
	pool   *pgxpool.Pool
	sender notifier.Sender
	ttl    time.Duration
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{pool: pool, sender: sender, ttl: ttl}
}

func (s *Service) StartEmail(ctx context.Context, userID uuid.UUID, email string) error {
	// Default to the address on file so the caller doesn't have to pass their
	// own email just to verify it (POST .../verify/email/start with no body).
	if strings.TrimSpace(email) == "" {
		if err := s.pool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, userID).Scan(&email); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrNotFound.WithDetail("user not found")
			}
			return err
		}
	}
	if strings.TrimSpace(email) == "" {
		return errs.ErrUnprocessable.WithMessage("This account has no email address to verify.")
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO "user".email_verifications (user_id, email, code_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, email, codes.Hash(code), time.Now().UTC().Add(s.ttl)); err != nil {
		return err
	}
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Your verification code is %s. It expires in %s.", code, s.ttl),
	})
}

func (s *Service) ConfirmEmail(ctx context.Context, userID uuid.UUID, code string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, expires_at, used_at
		FROM "user".email_verifications
		WHERE user_id = $1 AND code_hash = $2
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID, codes.Hash(code)).Scan(&id, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrBadRequest.WithDetail("invalid code")
		}
		return err
	}
	if usedAt != nil {
		return errs.ErrBadRequest.WithDetail("code already used")
	}
	if time.Now().After(expiresAt) {
		return errs.ErrBadRequest.WithDetail("code expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE "user".email_verifications SET used_at = NOW() WHERE id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE "user".users SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
		WHERE id = $1
	`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) StartPhone(ctx context.Context, userID uuid.UUID, phone string) error {
	// Default to the number on file when the body omits it.
	if strings.TrimSpace(phone) == "" {
		var stored *string
		if err := s.pool.QueryRow(ctx, `SELECT phone FROM "user".users WHERE id = $1`, userID).Scan(&stored); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrNotFound.WithDetail("user not found")
			}
			return err
		}
		if stored == nil || strings.TrimSpace(*stored) == "" {
			return errs.ErrUnprocessable.WithMessage("This account has no phone number to verify. Add one first.")
		}
		phone = *stored
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO "user".phone_verifications (user_id, phone, code_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, phone, codes.Hash(code), time.Now().UTC().Add(s.ttl)); err != nil {
		return err
	}
	return s.sender.Send(ctx, notifier.Message{
		Channel: "sms",
		To:      phone,
		Body:    fmt.Sprintf("Your Qeet verification code is %s", code),
	})
}

func (s *Service) ConfirmPhone(ctx context.Context, userID uuid.UUID, code string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, expires_at, used_at
		FROM "user".phone_verifications
		WHERE user_id = $1 AND code_hash = $2
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID, codes.Hash(code)).Scan(&id, &expiresAt, &usedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrBadRequest.WithDetail("invalid code")
		}
		return err
	}
	if usedAt != nil {
		return errs.ErrBadRequest.WithDetail("code already used")
	}
	if time.Now().After(expiresAt) {
		return errs.ErrBadRequest.WithDetail("code expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE "user".phone_verifications SET used_at = NOW() WHERE id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE "user".users SET phone_verified_at = COALESCE(phone_verified_at, NOW()), updated_at = NOW()
		WHERE id = $1
	`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
