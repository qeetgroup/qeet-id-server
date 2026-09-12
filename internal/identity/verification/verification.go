// Package verification handles "send-a-code, prove-you-own-it" flows for
// email and phone. The Sender abstraction lets us swap SendGrid / Twilio
// at the boundary; tests use the LogSender.
package verification

import (
	"context"
	"crypto/subtle"
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

// latestCode is the newest outstanding verification row for a user, together
// with the hash of the code it was issued for.
type latestCode struct {
	id        uuid.UUID
	codeHash  string
	value     string // the email or phone carried on the row
	expiresAt time.Time
	usedAt    *time.Time
	attempts  int
}

// maxVerificationAttempts is the guess budget for a single code. Five wrong
// answers retire it, so a 6-digit code can't be ground down: getting a fresh
// budget means requesting a new code, and the sending routes are throttled.
const maxVerificationAttempts = 5

// matches reports whether the submitted code is the one this row was issued
// for, compared in constant time so a wrong code can't be recovered by timing.
func (l latestCode) matches(code string) bool {
	return subtle.ConstantTimeCompare([]byte(codes.Hash(code)), []byte(l.codeHash)) == 1
}

// newestEmailCode / newestPhoneCode read the most recent row for a user and
// lock it for update.
//
// They deliberately do NOT filter on the submitted code's hash. The generated
// GetLatest*Verification queries match on (user_id, code_hash), which means the
// "latest" row is the latest one *for that code* — so every code ever issued
// stayed valid until it expired, and asking for a resend left the previous code
// working alongside the new one. Selecting the newest row and comparing the
// hash in Go makes "only the most recently sent code is accepted" a property of
// the lookup itself.
//
// Note both email flows (verify-your-address and change-your-address) write to
// email_verifications, and the table has no column distinguishing them, so the
// newest code wins across both. That is the intended reading: whichever code we
// most recently sent the user is the only one that counts.
//
// Raw SQL because sqlc isn't wired into the build here; fold these into
// queries.sql at the next `sqlc generate`.
func newestEmailCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (latestCode, error) {
	var l latestCode
	err := tx.QueryRow(ctx, `
		SELECT id, code_hash, email, expires_at, used_at, attempts
		FROM "user".email_verifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID).Scan(&l.id, &l.codeHash, &l.value, &l.expiresAt, &l.usedAt, &l.attempts)
	return l, err
}

func newestPhoneCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (latestCode, error) {
	var l latestCode
	err := tx.QueryRow(ctx, `
		SELECT id, code_hash, phone, expires_at, used_at, attempts
		FROM "user".phone_verifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1
		FOR UPDATE
	`, userID).Scan(&l.id, &l.codeHash, &l.value, &l.expiresAt, &l.usedAt, &l.attempts)
	return l, err
}

// recordFailedAttempt charges one guess against the code and reports whether
// that exhausted the budget. Retiring the row here (used_at) means the very
// attempt that hits the cap also closes the code, rather than leaving one more
// usable guess behind.
//
// The caller must COMMIT after this even though it is about to return an error:
// the whole point is that a failed confirm has a persistent cost. Rolling back,
// which is the natural shape of the surrounding transaction, would discard the
// count and leave the budget infinite.
func recordFailedAttempt(ctx context.Context, tx pgx.Tx, table string, id uuid.UUID) (bool, error) {
	// #nosec G201 -- table is one of two package-local literals, never caller input.
	q := `UPDATE "user".` + table + `
		SET attempts = attempts + 1,
		    used_at  = CASE WHEN attempts + 1 >= $2 THEN NOW() ELSE used_at END
		WHERE id = $1
		RETURNING attempts >= $2`
	var exhausted bool
	err := tx.QueryRow(ctx, q, id, maxVerificationAttempts).Scan(&exhausted)
	return exhausted, err
}

// chargeFailure runs the shared checks and, when the submitted code is wrong,
// persists the failed attempt before returning. It commits the transaction on
// that path so the count survives the caller's deferred rollback.
func chargeFailure(ctx context.Context, tx pgx.Tx, table string, row latestCode, code string) error {
	err := checkUsable(row, code)
	if !errors.Is(err, errs.ErrVerifyCodeInvalid) {
		// Expired, already used, or budget already gone: nothing to charge, and
		// a correct code (err == nil) falls through to the caller's success path.
		return err
	}
	exhausted, updErr := recordFailedAttempt(ctx, tx, table, row.id)
	if updErr != nil {
		return updErr
	}
	if cmtErr := tx.Commit(ctx); cmtErr != nil {
		return cmtErr
	}
	if exhausted {
		return errs.ErrVerifyAttemptsExceeded
	}
	return err
}

// checkUsable applies the non-identity checks shared by every confirm path.
func checkUsable(l latestCode, code string) error {
	// Budget first, and before the identity check: once a code is burned it is
	// dead even for the correct value, so a guesser can't tell from the response
	// that they had finally landed on it.
	if l.attempts >= maxVerificationAttempts {
		return errs.ErrVerifyAttemptsExceeded
	}
	// A stale code (superseded by a resend) and a plain wrong code are the same
	// thing to the caller: this is not the code we are waiting on.
	if !l.matches(code) {
		return errs.ErrVerifyCodeInvalid
	}
	if l.usedAt != nil {
		return errs.ErrVerifyCodeUsed
	}
	if time.Now().After(l.expiresAt) {
		return errs.ErrVerifyCodeExpired
	}
	return nil
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

	row, err := newestEmailCode(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	if err := chargeFailure(ctx, tx, "email_verifications", row, code); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkEmailVerificationUsed(ctx, row.id); err != nil {
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

	row, err := newestEmailCode(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errs.ErrVerifyCodeInvalid
		}
		return "", err
	}
	if err := chargeFailure(ctx, tx, "email_verifications", row, code); err != nil {
		return "", err
	}
	if err := qtx.MarkEmailVerificationUsed(ctx, row.id); err != nil {
		return "", err
	}
	if _, err := qtx.UpdateUserEmail(ctx, dbgen.UpdateUserEmailParams{
		Email:  row.value,
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
	return row.value, nil
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

	row, err := newestPhoneCode(ctx, tx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrVerifyCodeInvalid
		}
		return err
	}
	if err := chargeFailure(ctx, tx, "phone_verifications", row, code); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).MarkPhoneVerificationUsed(ctx, row.id); err != nil {
		return err
	}
	// Persist the verified number itself (not just the timestamp) so downstream
	// SMS/OTP has a number to use and the account isn't left "verified" with a
	// NULL phone.
	if err := s.q.WithTx(tx).SetUserVerifiedPhone(ctx, dbgen.SetUserVerifiedPhoneParams{
		Phone:  &row.value,
		UserID: userID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
