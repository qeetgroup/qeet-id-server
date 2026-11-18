package verification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// The two flows that send email codes. A code proves only what its own flow
// asked: a verify_email code went to the address on file, a change_email code
// to the address the user wants to move to.
const (
	purposeVerifyEmail = "verify_email"
	purposeChangeEmail = "change_email"
)

// newestEmailCode locks and returns userID's most recent email code for
// purpose, in q's transaction: only the newest code can match, so a resend
// supersedes the code before it.
func newestEmailCode(ctx context.Context, q *dbgen.Queries, userID uuid.UUID, purpose string) (latestCode, error) {
	row, err := q.NewestEmailCode(ctx, dbgen.NewestEmailCodeParams{UserID: userID, Purpose: purpose})
	return latestCode{id: row.ID, codeHash: row.CodeHash, value: row.Email, expiresAt: row.ExpiresAt,
		usedAt: row.UsedAt, attempts: int(row.Attempts)}, err
}

// StartEmail sends a verification code to the user's email address.
func (s *Service) StartEmail(ctx context.Context, userID uuid.UUID, email string, who Requester) error {
	// Default to the address on file so the caller doesn't have to pass their
	// own email just to verify it (POST .../verify/email/start with no body).
	if strings.TrimSpace(email) == "" {
		addr, err := s.q.GetUserEmail(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrVerifyUserNotFound
			}
			return err
		}
		email = addr
	}
	if strings.TrimSpace(email) == "" {
		return ErrVerifyNoEmail
	}
	code, id, err := s.issueEmailCode(ctx, userID, email, purposeVerifyEmail, who)
	if err != nil {
		return err
	}
	expiry := fmt.Sprintf("%d minutes", int(s.ttl.Minutes()))
	return s.withdrawUndelivered(ctx, s.q.DeleteEmailVerification, id, s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Your Qeet ID verification code is %s. It expires in %s.", code, expiry),
		HTML: emailtmpl.Code(
			"Verify your email",
			"Use the code below to verify your email address.",
			code, expiry,
		),
	}))
}

// issueEmailCode stores a new code for one purpose (expiring the user's open
// codes) and audits it, in one transaction, unless the sending limits refuse
// it. It returns the code to send and its row.
func (s *Service) issueEmailCode(ctx context.Context, userID uuid.UUID, email, purpose string, who Requester) (string, uuid.UUID, error) {
	digits := 6
	if purpose == purposeChangeEmail {
		digits = changeEmailDigits
	}
	code, err := codes.Numeric(digits)
	if err != nil {
		return "", uuid.Nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)
	if err := qtx.LockAccountForCodeSend(ctx, userID); err != nil {
		return "", uuid.Nil, err
	}
	sent, err := qtx.EmailCodeSends(ctx, dbgen.EmailCodeSendsParams{UserID: userID, Email: email})
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := (codeSends{mine: sent.UserSends, mineOldest: sent.UserOldest, toAddress: sent.AddressSends,
		addressOldest: sent.AddressOldest}).limit(); err != nil {
		return "", uuid.Nil, err
	}
	id, err := qtx.InsertEmailVerification(ctx, dbgen.InsertEmailVerificationParams{
		UserID:    userID,
		Email:     email,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
		Purpose:   purpose,
	})
	if err != nil {
		return "", uuid.Nil, err
	}
	if err := audit.Record(ctx, tx, who.event("email.verification_started", userID,
		map[string]any{"purpose": purpose, "email": email})); err != nil {
		return "", uuid.Nil, err
	}
	return code, id, tx.Commit(ctx)
}

// emailBudget returns userID's guesses at purpose's codes this hour, in tx.
func emailBudget(ctx context.Context, tx pgx.Tx, userID uuid.UUID, purpose string) (guessBudget, error) {
	row, err := dbgen.New(tx).EmailCodeFailures(ctx, dbgen.EmailCodeFailuresParams{UserID: userID, Purpose: purpose})
	return guessBudget{failures: int(row.Failures), oldest: row.Oldest}, err
}

// ConfirmEmail verifies the address on file with a verify_email code. The code
// must have been sent to that address: one sent elsewhere (for an address
// change, or before the address changed) is the invalid-code error.
func (s *Service) ConfirmEmail(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	err := s.confirmEmail(ctx, userID, code, who)
	return s.auditRefusal(ctx, "email.verification_failed", userID, map[string]any{"purpose": purposeVerifyEmail}, who, err)
}

func (s *Service) confirmEmail(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	row, err := newestEmailCode(ctx, qtx, userID, purposeVerifyEmail)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrVerifyCodeInvalid
		}
		return err
	}
	budget, err := emailBudget(ctx, tx, userID, purposeVerifyEmail)
	if err != nil {
		return err
	}
	if err := chargeFailure(ctx, tx, row, code, budget); err != nil {
		return err
	}
	n, err := qtx.MarkUserEmailVerified(ctx, dbgen.MarkUserEmailVerifiedParams{UserID: userID, Email: row.value})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrVerifyCodeInvalid
	}
	if err := qtx.MarkEmailVerificationUsed(ctx, row.id); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("email.verified", userID,
		map[string]any{"email": row.value, "proof": "emailed_code"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
