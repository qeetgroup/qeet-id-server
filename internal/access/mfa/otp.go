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
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
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

// Limits on email and SMS codes, at the pace of a person asking for one, so
// the service cannot be used to flood an inbox or phone or run up SMS bills.
const (
	otpResendAfter                = 30 * time.Second // wait before another code to the same factor
	otpSendsPerHourPerUser        = 10               // codes per person per hour, over all their factors
	otpSendsPerHourPerDestination = 5                // codes per address or number per hour, over all accounts
	maxOTPFactors                 = 5                // email and SMS factors one person may hold
)

// otpSend is one code to send: whose, in which organization (nil: none; it
// decides whether SMS is in the plan), to which factor, and why ("enrollment",
// "step_up" or "sign_in", as audited).
type otpSend struct {
	userID         uuid.UUID
	organizationID *uuid.UUID
	factorID       uuid.UUID
	channel        string
	destination    string
	purpose        string
}

// sendOTP sends a fresh code to a factor, ending its earlier unused codes, and
// audits the send with the destination masked. It fails with
// ErrMFACodeSendLimited (retry_after in seconds) inside the resend wait or past
// an hourly limit, and refuses SMS unless the organization's plan includes it.
func (s *Service) sendOTP(ctx context.Context, in otpSend) error {
	if !s.deliverable(in.channel) {
		return ErrDeliveryUnavailable.WithMetadata(map[string]any{"channel": in.channel})
	}
	if in.channel == "sms" {
		if in.organizationID == nil {
			return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sms_mfa"})
		}
		ok, err := s.plan.FeatureAllowed(ctx, *in.organizationID, "sms_mfa")
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
	q := s.q.WithTx(tx)
	// One send at a time per factor, so two requests cannot both pass the wait.
	if err := q.LockOTPFactor(ctx, in.factorID); err != nil {
		return err
	}
	if wait, err := otpSendWait(ctx, q, in); err != nil {
		return err
	} else if wait > 0 {
		return errs.ErrMFACodeSendLimited.WithMetadata(map[string]any{"retry_after": int(wait.Round(time.Second).Seconds())})
	}
	if err := q.ExpireLiveOTPCodes(ctx, in.factorID); err != nil {
		return err
	}
	if err := q.InsertMFAOTPCode(ctx, dbgen.InsertMFAOTPCodeParams{
		FactorID:  in.factorID,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(otpTTL),
		Purpose:   in.purpose,
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, in.event("mfa.otp_sent")); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: in.channel,
		To:      in.destination,
		Subject: "Your verification code",
		Body:    fmt.Sprintf(otpWording[in.purpose], s.issuer, code, otpTTL),
	}); err != nil {
		s.undeliveredOTP(ctx, in, code)
		return errs.ErrMFADeliveryFailed.Wrap(err)
	}
	return nil
}

// otpWording is each purpose's message, so a person asked for a code knows
// what entering it will do.
var otpWording = map[string]string{
	"sign_in":    "Your %s sign-in code is %s. It expires in %s.",
	"step_up":    "Your %s code to confirm a change to your account's security is %s. It expires in %s.",
	"enrollment": "Your %s code to add this as a way to verify your sign-ins is %s. It expires in %s.",
}

// event is the audit event of action on in's code, by its person, with the
// destination masked.
func (in otpSend) event(action string) audit.Event {
	return audit.Actor{UserID: &in.userID, Type: "user"}.EventIn(in.organizationID, action, "mfa_factor", in.factorID,
		map[string]any{"channel": in.channel, "destination": notifier.MaskDestination(in.channel, in.destination), "purpose": in.purpose})
}

// undeliveredOTP withdraws a code the provider did not take, so it counts
// against no limit and can never be used, and audits the failure. Best effort:
// the caller already reports the failure.
func (s *Service) undeliveredOTP(ctx context.Context, in otpSend, code string) {
	_ = s.inTx(ctx, func(tx pgx.Tx) error {
		if err := s.q.WithTx(tx).WithdrawOTPCode(ctx, dbgen.WithdrawOTPCodeParams{FactorID: in.factorID, CodeHash: codes.Hash(code)}); err != nil {
			return err
		}
		return audit.Record(ctx, tx, in.event("mfa.otp_delivery_failed"))
	})
}

// otpSendWait is how long until another code may go to in's factor: the rest
// of otpResendAfter since its last code, or until the oldest send counted
// against an hourly limit leaves the hour. Zero: one may go now.
func otpSendWait(ctx context.Context, q *dbgen.Queries, in otpSend) (time.Duration, error) {
	sent, err := q.OTPSendHistory(ctx, dbgen.OTPSendHistoryParams{
		FactorID: in.factorID, UserID: in.userID, Channel: in.channel, Destination: in.destination,
	})
	if err != nil {
		return 0, err
	}
	var wait time.Duration
	later := func(d time.Duration) {
		if d > wait {
			wait = d
		}
	}
	// With no code to go by a time is the epoch, which imposes no wait.
	later(otpResendAfter - time.Since(sent.FactorLast))
	if sent.UserHour >= otpSendsPerHourPerUser {
		later(time.Hour - time.Since(sent.UserOldest))
	}
	if sent.DestinationHour >= otpSendsPerHourPerDestination {
		later(time.Hour - time.Since(sent.DestinationOldest))
	}
	if wait > 0 && wait < time.Second {
		wait = time.Second
	}
	return wait, nil
}

// EnrollOTPStart registers (or re-arms) a channel and sends a confirmation
// code. The factor is unverified until EnrollOTPConfirm succeeds. organizationID is
// the caller's organization (nil: none), whose plan decides SMS. A person may
// hold at most maxOTPFactors email and SMS factors.
func (s *Service) EnrollOTPStart(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, channel, destination string) (uuid.UUID, error) {
	channel = strings.ToLower(strings.TrimSpace(channel))
	destination = strings.TrimSpace(destination)
	if channel != "email" && channel != "sms" {
		return uuid.Nil, ErrChannelInvalid
	}
	if destination == "" {
		return uuid.Nil, ErrDestinationRequired
	}
	if !s.deliverable(channel) {
		return uuid.Nil, ErrDeliveryUnavailable.WithMetadata(map[string]any{"channel": channel})
	}
	holdings, err := s.q.OTPFactorHoldings(ctx, dbgen.OTPFactorHoldingsParams{UserID: userID, Channel: channel, Destination: destination})
	if err != nil {
		return uuid.Nil, err
	}
	if !holdings.Already && holdings.Held >= maxOTPFactors {
		return uuid.Nil, ErrFactorLimit
	}
	factorID, err := s.q.UpsertMFAOTPFactor(ctx, dbgen.UpsertMFAOTPFactorParams{
		UserID:      userID,
		Channel:     channel,
		Destination: destination,
	})
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.sendOTP(ctx, otpSend{userID: userID, organizationID: organizationID, factorID: factorID, channel: channel,
		destination: destination, purpose: "enrollment"}); err != nil {
		return uuid.Nil, err
	}
	return factorID, nil
}

// EnrollOTPConfirm verifies the code sent to userID's factor and marks the
// factor usable, recorded as by's. Each try spends one of the attempts at
// confirming that factor.
func (s *Service) EnrollOTPConfirm(ctx context.Context, userID, factorID uuid.UUID, code string, by Caller) error {
	return s.withAttempt(ctx, userID, PurposeOTPEnroll(factorID), func(attempt Attempt) error {
		return s.inTx(ctx, func(tx pgx.Tx) error {
			if err := s.enrollOTPConfirm(ctx, tx, attempt, factorID, code); err != nil {
				return err
			}
			return audit.Record(ctx, tx, by.event("mfa.otp_factor_added", userID, nil))
		})
	})
}

// enrollOTPConfirm is EnrollOTPConfirm inside tx with a reserved attempt,
// unaudited.
func (s *Service) enrollOTPConfirm(ctx context.Context, tx pgx.Tx, attempt Attempt, factorID uuid.UUID, code string) error {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForConfirm(ctx, dbgen.GetOTPCodeForConfirmParams{
		ID:       factorID,
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return attemptError(ErrOTPCodeInvalid, attempt.remaining)
	}
	if err != nil {
		return err
	}
	n, err := qtx.MarkOTPCodeUsed(ctx, codeID)
	if err != nil {
		return err
	}
	if n != 1 {
		return attemptError(ErrOTPCodeInvalid, attempt.remaining)
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
			Destination: notifier.MaskDestination(m.Channel, m.Destination),
			Verified:    m.VerifiedAt != nil,
			CreatedAt:   m.CreatedAt,
		})
	}
	return out, nil
}

// DeleteOTPFactor removes one of userID's SMS or email factors, recorded as
// by's.
func (s *Service) DeleteOTPFactor(ctx context.Context, userID, factorID uuid.UUID, by Caller) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		if err := s.deleteOTPFactor(ctx, tx, userID, factorID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, by.event("mfa.otp_factor_removed", userID, nil))
	})
}

// deleteOTPFactor is DeleteOTPFactor inside tx, unaudited.
func (s *Service) deleteOTPFactor(ctx context.Context, tx pgx.Tx, userID, factorID uuid.UUID) error {
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

// ChallengeOTP sends a fresh code to a verified factor for a step-up. organizationID
// is the caller's organization (nil: none), whose plan decides SMS.
func (s *Service) ChallengeOTP(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, factorID uuid.UUID) error {
	return s.challengeOTP(ctx, userID, organizationID, factorID, "step_up")
}

func (s *Service) challengeOTP(ctx context.Context, userID uuid.UUID, organizationID *uuid.UUID, factorID uuid.UUID, purpose string) error {
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
	if row.VerifiedAt == nil {
		return ErrFactorNotConfirmed
	}
	return s.sendOTP(ctx, otpSend{userID: userID, organizationID: organizationID, factorID: factorID, channel: row.Channel,
		destination: row.Destination, purpose: purpose})
}

// VerifyOTP consumes a step-up code sent to any of userID's verified OTP
// factors, a sign-in code never counting, and steps up by's session.
// ErrMFACodeInvalid for a wrong code; each try spends one of the person's
// attempts.
func (s *Service) VerifyOTP(ctx context.Context, userID uuid.UUID, code string, by Caller) error {
	return s.withAttempt(ctx, userID, PurposeOTPVerify, func(attempt Attempt) error {
		return s.inTx(ctx, func(tx pgx.Tx) error {
			ok, err := s.verifyOTP(ctx, tx, attempt, code)
			if err != nil {
				return err
			}
			if !ok {
				return errs.ErrMFACodeInvalid
			}
			return s.recordStepUp(ctx, tx, userID, by, "otp")
		})
	})
}

// verifyOTP is VerifyOTP inside tx with a reserved attempt, unrecorded.
func (s *Service) verifyOTP(ctx context.Context, tx pgx.Tx, attempt Attempt, code string) (bool, error) {
	userID := attempt.userID
	qtx := s.q.WithTx(tx)
	codeID, err := qtx.GetOTPCodeForVerify(ctx, dbgen.GetOTPCodeForVerifyParams{
		UserID:   userID,
		CodeHash: codes.Hash(strings.TrimSpace(code)),
		Purpose:  "step_up",
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err != nil {
		return false, err
	}
	n, err := qtx.MarkOTPCodeUsed(ctx, codeID)
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, attemptError(errs.ErrMFACodeInvalid, attempt.remaining)
	}
	if err := clearMFAAttempt(ctx, tx, userID, attempt.purpose); err != nil {
		return false, err
	}
	return true, nil
}
