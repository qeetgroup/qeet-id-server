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

	"github.com/qeetgroup/qeet-id-server/domains/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/platform/api/rest/codes"
	"github.com/qeetgroup/qeet-id-server/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id-server/platform/messaging/notifier"
)

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	sender notifier.Sender
	ttl    time.Duration
}

func NewService(pool *pgxpool.Pool, sender notifier.Sender, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{pool: pool, q: dbgen.New(pool), sender: sender, ttl: ttl}
}

func (s *Service) StartEmail(ctx context.Context, userID uuid.UUID, email string) error {
	// Default to the address on file so the caller doesn't have to pass their
	// own email just to verify it (POST .../verify/email/start with no body).
	if strings.TrimSpace(email) == "" {
		addr, err := s.q.GetUserEmail(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrNotFound.WithDetail("user not found")
			}
			return err
		}
		email = addr
	}
	if strings.TrimSpace(email) == "" {
		return errs.ErrUnprocessable.WithMessage("This account has no email address to verify.")
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if err := s.q.InsertEmailVerification(ctx, dbgen.InsertEmailVerificationParams{
		UserID:    userID,
		Email:     email,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
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

	row, err := s.q.WithTx(tx).GetLatestEmailVerification(ctx, dbgen.GetLatestEmailVerificationParams{
		UserID:   userID,
		CodeHash: codes.Hash(code),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrBadRequest.WithDetail("invalid code")
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrBadRequest.WithDetail("code already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrBadRequest.WithDetail("code expired")
	}
	if err := s.q.WithTx(tx).MarkEmailVerificationUsed(ctx, row.ID); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkUserEmailVerified(ctx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) StartPhone(ctx context.Context, userID uuid.UUID, phone string) error {
	// Default to the number on file when the body omits it.
	if strings.TrimSpace(phone) == "" {
		stored, err := s.q.GetUserPhone(ctx, userID)
		if err != nil {
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
	if err := s.q.InsertPhoneVerification(ctx, dbgen.InsertPhoneVerificationParams{
		UserID:    userID,
		Phone:     phone,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
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

	row, err := s.q.WithTx(tx).GetLatestPhoneVerification(ctx, dbgen.GetLatestPhoneVerificationParams{
		UserID:   userID,
		CodeHash: codes.Hash(code),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrBadRequest.WithDetail("invalid code")
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrBadRequest.WithDetail("code already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrBadRequest.WithDetail("code expired")
	}
	if err := s.q.WithTx(tx).MarkPhoneVerificationUsed(ctx, row.ID); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkUserPhoneVerified(ctx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
