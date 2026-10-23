package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

const otpTTL = 10 * time.Minute

// OTPFactor is the account-facing view of a registered OTP channel. The
// destination is masked so the UI can show which factor without exposing the
// full address/number.
type OTPFactor struct {
	ID          uuid.UUID `json:"id"`
	Channel     string    `json:"channel"`
	Destination string    `json:"destination"`
	Verified    bool      `json:"verified"`
	CreatedAt   time.Time `json:"created_at"`
}

func maskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at <= 1 {
			return dest
		}
		return dest[:1] + strings.Repeat("*", at-1) + dest[at:]
	}
	// phone: keep the last 3 digits.
	if len(dest) <= 3 {
		return dest
	}
	return strings.Repeat("*", len(dest)-3) + dest[len(dest)-3:]
}

// Limits on email and SMS codes, at the pace of a person asking for one, so
// the service cannot be used to flood an inbox or phone or run up SMS bills.
const (
	otpResendAfter                = 30 * time.Second // wait before another code to the same factor
	otpSendsPerHourPerUser        = 10               // codes per person per hour, over all their factors
	otpSendsPerHourPerDestination = 5                // codes per address or number per hour, over all accounts
	maxOTPFactors                 = 5                // email and SMS factors one person may hold
)

// otpSend is one code to send: whose, in which organisation (nil: none; it
// decides whether SMS is in the plan), to which factor, and why ("enrollment",
// "step_up" or "sign_in", as audited).
type otpSend struct {
	userID      uuid.UUID
	tenantID    *uuid.UUID
	factorID    uuid.UUID
	channel     string
	destination string
	purpose     string
}

// sendOTP sends a fresh code to a factor, ending its earlier unused codes, and
// audits the send with the destination masked. It fails with
// ErrMFACodeSendLimited (retry_after in seconds) inside the resend wait or past
// an hourly limit, and refuses SMS unless the organisation's plan includes it.
func (s *Service) sendOTP(ctx context.Context, in otpSend) error {
	if s.deliverable != nil && !s.deliverable(in.channel) {
		return errs.ErrMFADeliveryUnavailable.WithMetadata(map[string]any{"channel": in.channel})
	}
	if in.channel == "sms" && s.plan != nil {
		if in.tenantID == nil {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sms_mfa"})
		}
		ok, err := s.plan.FeatureAllowed(ctx, *in.tenantID, "sms_mfa")
		if err != nil {
			return err
		}
		if !ok {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sms_mfa"})
		}
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// One send at a time per factor, so two requests cannot both pass the wait.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM auth.mfa_otp_factors WHERE id = $1 FOR UPDATE`, in.factorID); err != nil {
		return err
	}
	if wait, err := otpSendWait(ctx, tx, in); err != nil {
		return err
	} else if wait > 0 {
		return errs.ErrMFACodeSendLimited.WithMetadata(map[string]any{"retry_after": int(wait.Round(time.Second).Seconds())})
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_otp_codes SET expires_at = NOW()
		WHERE factor_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`, in.factorID); err != nil {
		return err
	}
	if err := s.q.WithTx(tx).InsertMFAOTPCode(ctx, dbgen.InsertMFAOTPCodeParams{
		FactorID:  in.factorID,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(otpTTL),
	}); err != nil {
		return err
	}
	factor := in.factorID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     in.tenantID,
		ActorUserID:  &in.userID,
		ActorType:    "user",
		Action:       "mfa.otp_sent",
		ResourceType: "mfa_factor",
		ResourceID:   &factor,
		Metadata: map[string]any{"channel": in.channel, "destination": maskDestination(in.channel, in.destination),
			"purpose": in.purpose},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: in.channel,
		To:      in.destination,
		Subject: "Your verification code",
		Body:    fmt.Sprintf("Your %s sign-in code is %s. It expires in %s.", s.issuer, code, otpTTL),
	}); err != nil {
		s.undeliveredOTP(ctx, in, code)
		return errs.ErrMFADeliveryFailed.Wrap(err)
	}
	return nil
}

// undeliveredOTP withdraws a code the provider did not take, so it counts
// against no limit and can never be used, and audits the failure. Best effort:
// the caller already reports the failure.
func (s *Service) undeliveredOTP(ctx context.Context, in otpSend, code string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_otp_codes WHERE factor_id = $1 AND code_hash = $2`,
		in.factorID, codes.Hash(code)); err != nil {
		return
	}
	factor := in.factorID
	if audit.Record(ctx, tx, audit.Event{
		TenantID: in.tenantID, ActorUserID: &in.userID, ActorType: "user",
		Action: "mfa.otp_delivery_failed", ResourceType: "mfa_factor", ResourceID: &factor,
		Metadata: map[string]any{"channel": in.channel, "destination": maskDestination(in.channel, in.destination),
			"purpose": in.purpose},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// otpSendWait is how long until another code may go to in's factor: the rest
// of otpResendAfter since its last code, or until the oldest send counted
// against an hourly limit leaves the hour. Zero: one may go now.
func otpSendWait(ctx context.Context, tx pgx.Tx, in otpSend) (time.Duration, error) {
	var factorLast, userOldest, destOldest *time.Time
	var userHour, destHour int
	if err := tx.QueryRow(ctx, `
		SELECT
		    (SELECT max(c.created_at) FROM auth.mfa_otp_codes c WHERE c.factor_id = $1),
		    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.user_id = $2 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.user_id = $2 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.channel = $3 AND f.destination = $4 AND c.created_at > NOW() - INTERVAL '1 hour'),
		    (SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		      WHERE f.channel = $3 AND f.destination = $4 AND c.created_at > NOW() - INTERVAL '1 hour')
	`, in.factorID, in.userID, in.channel, in.destination).
		Scan(&factorLast, &userHour, &userOldest, &destHour, &destOldest); err != nil {
		return 0, err
	}
	var wait time.Duration
	later := func(d time.Duration) {
		if d > wait {
			wait = d
		}
	}
	if factorLast != nil {
		later(otpResendAfter - time.Since(*factorLast))
	}
	if userHour >= otpSendsPerHourPerUser && userOldest != nil {
		later(time.Hour - time.Since(*userOldest))
	}
	if destHour >= otpSendsPerHourPerDestination && destOldest != nil {
		later(time.Hour - time.Since(*destOldest))
	}
	if wait > 0 && wait < time.Second {
		wait = time.Second
	}
	return wait, nil
}

// EnrollOTPStart registers (or re-arms) a channel and sends a confirmation
// code. The factor is unverified until EnrollOTPConfirm succeeds. tenantID is
// the caller's organisation (nil: none), whose plan decides SMS. A person may
// hold at most maxOTPFactors email and SMS factors.
func (s *Service) EnrollOTPStart(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, channel, destination string) (uuid.UUID, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	destination = strings.TrimSpace(destination)
	if channel != "email" && channel != "sms" {
		return uuid.Nil, errs.ErrMFAChannelInvalid
	}
	if destination == "" {
		return uuid.Nil, errs.ErrMFADestinationRequired
	}
	if s.deliverable != nil && !s.deliverable(channel) {
		return uuid.Nil, errs.ErrMFADeliveryUnavailable.WithMetadata(map[string]any{"channel": channel})
	}
	var held int
	var already bool
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(bool_or(channel = $2 AND destination = $3), FALSE)
		FROM auth.mfa_otp_factors WHERE user_id = $1
	`, userID, channel, destination).Scan(&held, &already); err != nil {
		return uuid.Nil, err
	}
	if !already && held >= maxOTPFactors {
		return uuid.Nil, errs.ErrMFAFactorLimit
	}
	factorID, err := s.q.UpsertMFAOTPFactor(ctx, dbgen.UpsertMFAOTPFactorParams{
		UserID:      userID,
		Channel:     channel,
		Destination: destination,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.sendOTP(ctx, otpSend{userID: userID, tenantID: tenantID, factorID: factorID, channel: channel,
		destination: destination, purpose: "enrollment"}); err != nil {
		return uuid.Nil, err
	}
	return factorID, nil
}

// EnrollOTPConfirm verifies the code and marks the factor usable.
func (s *Service) EnrollOTPConfirm(ctx context.Context, tx pgx.Tx, attempt Attempt, factorID uuid.UUID, code string) error {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForConfirm(ctx, dbgen.GetOTPCodeForConfirmParams{
		ID:       factorID,
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return attemptError(errs.ErrMFAOTPCodeInvalid, attempt.remaining)
	}
	if err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return attemptError(errs.ErrMFAOTPCodeInvalid, attempt.remaining)
	}
	if err := qtx.MarkOTPFactorVerified(ctx, factorID); err != nil {
		return err
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return err
	}
	return nil
}

// ListOTPFactors returns the user's SMS and email factors.
func (s *Service) ListOTPFactors(ctx context.Context, userID uuid.UUID) ([]OTPFactor, error) {
	rows, err := s.q.ListOTPFactors(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]OTPFactor, 0, len(rows))
	for _, m := range rows {
		out = append(out, OTPFactor{
			ID:          m.ID,
			Channel:     m.Channel,
			Destination: maskDestination(m.Channel, m.Destination),
			Verified:    m.VerifiedAt.Valid,
			CreatedAt:   m.CreatedAt,
		})
	}
	return out, nil
}

// DeleteOTPFactor removes one of the user's SMS or email factors.
func (s *Service) DeleteOTPFactor(ctx context.Context, tx pgx.Tx, userID, factorID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteOTPFactor(ctx, dbgen.DeleteOTPFactorParams{
		ID:     factorID,
		UserID: userID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// ChallengeOTP sends a fresh code to a verified factor for a step-up. tenantID
// is the caller's organisation (nil: none), whose plan decides SMS.
func (s *Service) ChallengeOTP(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID) error {
	return s.challengeOTP(ctx, userID, tenantID, factorID, "step_up")
}

func (s *Service) challengeOTP(ctx context.Context, userID uuid.UUID, tenantID *uuid.UUID, factorID uuid.UUID, purpose string) error {
	row, err := s.q.GetOTPFactorForChallenge(ctx, dbgen.GetOTPFactorForChallengeParams{
		ID:     factorID,
		UserID: userID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if !row.VerifiedAt.Valid {
		return errs.ErrMFAFactorNotConfirmed
	}
	return s.sendOTP(ctx, otpSend{userID: userID, tenantID: tenantID, factorID: factorID, channel: row.Channel,
		destination: row.Destination, purpose: purpose})
}

// VerifyOTP consumes a code from any of the user's verified OTP factors.
func (s *Service) VerifyOTP(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) (bool, error) {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForVerify(ctx, dbgen.GetOTPCodeForVerifyParams{
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL`, codeID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return false, err
	}
	return true, nil
}
