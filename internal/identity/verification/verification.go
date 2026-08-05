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

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
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
				return errs.ErrVerifyUserNotFound
			}
			return err
		}
		email = addr
	}
	if strings.TrimSpace(email) == "" {
		return errs.ErrVerifyNoEmail
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
	expiry := fmt.Sprintf("%d minutes", int(s.ttl.Minutes()))
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Your Qeet ID verification code is %s. It expires in %s.", code, expiry),
		HTML: emailtmpl.Code(
			"Verify your email",
			"Use the code below to verify your email address.",
			code, expiry,
		),
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
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrVerifyCodeUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrVerifyCodeExpired
	}
	if err := s.q.WithTx(tx).MarkEmailVerificationUsed(ctx, row.ID); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkUserEmailVerified(ctx, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// StartEmailChange sends a verification code to a *new* address the user wants
// to move to. It pre-checks that no other account already owns that address
// (email is globally unique) and sends the code to the new address, since that's
// the one whose control we're proving.
func (s *Service) StartEmailChange(ctx context.Context, userID uuid.UUID, newEmail string) error {
	newEmail = strings.TrimSpace(newEmail)
	if newEmail == "" {
		return errs.ErrVerifyNoEmail
	}
	taken, err := s.q.EmailTakenByOther(ctx, dbgen.EmailTakenByOtherParams{
		Email:  newEmail,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if taken {
		return errs.ErrEmailTaken
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if err := s.q.InsertEmailVerification(ctx, dbgen.InsertEmailVerificationParams{
		UserID:    userID,
		Email:     newEmail,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	}); err != nil {
		return err
	}
	expiry := fmt.Sprintf("%d minutes", int(s.ttl.Minutes()))
	return s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      newEmail,
		Subject: "Confirm your new email",
		Body:    fmt.Sprintf("Your Qeet ID email-change code is %s. It expires in %s.", code, expiry),
		HTML: emailtmpl.Code(
			"Confirm your new email",
			"Use the code below to confirm your new email address.",
			code, expiry,
		),
	})
}

// ConfirmEmailChange verifies the code sent to the new address and swaps it onto
// the user (marking it verified). Returns the new email on success. A unique
// violation (address claimed between start and confirm) maps to ErrEmailTaken.
func (s *Service) ConfirmEmailChange(ctx context.Context, userID uuid.UUID, code string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	row, err := qtx.GetLatestEmailChange(ctx, dbgen.GetLatestEmailChangeParams{
		UserID:   userID,
		CodeHash: codes.Hash(code),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errs.ErrVerifyCodeInvalid
		}
		return "", err
	}
	if row.UsedAt.Valid {
		return "", errs.ErrVerifyCodeUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return "", errs.ErrVerifyCodeExpired
	}
	if err := qtx.MarkEmailVerificationUsed(ctx, row.ID); err != nil {
		return "", err
	}
	if _, err := qtx.UpdateUserEmail(ctx, dbgen.UpdateUserEmailParams{
		Email:  row.Email,
		UserID: userID,
	}); err != nil {
		if pgxerr.IsUnique(err) {
			return "", errs.ErrEmailTaken
		}
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return row.Email, nil
}

func (s *Service) StartPhone(ctx context.Context, userID uuid.UUID, phone string) error {
	// Default to the number on file when the body omits it.
	if strings.TrimSpace(phone) == "" {
		stored, err := s.q.GetUserPhone(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return errs.ErrVerifyUserNotFound
			}
			return err
		}
		if stored == nil || strings.TrimSpace(*stored) == "" {
			return errs.ErrVerifyNoPhone
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
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	if row.UsedAt.Valid {
		return errs.ErrVerifyCodeUsed
	}
	if time.Now().After(row.ExpiresAt) {
		return errs.ErrVerifyCodeExpired
	}
	if err := s.q.WithTx(tx).MarkPhoneVerificationUsed(ctx, row.ID); err != nil {
		return err
	}
	// Persist the verified number itself (not just the timestamp) so downstream
	// SMS/OTP has a number to use and the account isn't left "verified" with a
	// NULL phone.
	if err := s.q.WithTx(tx).SetUserVerifiedPhone(ctx, dbgen.SetUserVerifiedPhoneParams{
		Phone:  &row.Phone,
		UserID: userID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
