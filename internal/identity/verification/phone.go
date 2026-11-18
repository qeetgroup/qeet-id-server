package verification

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/verification/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// e164 matches a phone number in E.164 form: +, a country code, at most 15 digits.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// errVerifyPhoneInvalid refuses a number that isn't in E.164 form.
var errVerifyPhoneInvalid = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "phone", Code: "invalid_phone", Message: "Must be a valid phone number in E.164 format.",
}})

// newestPhoneCode is newestEmailCode for phone codes.
func newestPhoneCode(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (latestCode, error) {
	row, err := q.NewestPhoneCode(ctx, userID)
	return latestCode{id: row.ID, codeHash: row.CodeHash, value: row.Phone, expiresAt: row.ExpiresAt,
		usedAt: row.UsedAt, attempts: int(row.Attempts), phone: true}, err
}

// StartPhone sends a verification code to the user's phone number, recorded as
// who's with the number masked. As for MFA codes, the number must be in E.164
// form, and SMS deliverable and in the plan of the organization who's session
// is in (none: refused).
func (s *Service) StartPhone(ctx context.Context, userID uuid.UUID, phone string, who Requester) error {
	// Default to the number on file when the body omits it.
	if strings.TrimSpace(phone) == "" {
		stored, err := s.q.GetUserPhone(ctx, userID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrVerifyUserNotFound
			}
			return err
		}
		if stored == nil || strings.TrimSpace(*stored) == "" {
			return ErrVerifyNoPhone
		}
		phone = *stored
	}
	if err := s.canSendSMS(ctx, phone, who.OrganizationID); err != nil {
		return err
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
	qtx := s.q.WithTx(tx)
	if err := qtx.LockAccountForCodeSend(ctx, userID); err != nil {
		return err
	}
	sent, err := qtx.PhoneCodeSends(ctx, dbgen.PhoneCodeSendsParams{UserID: userID, Phone: phone})
	if err != nil {
		return err
	}
	if err := (codeSends{mine: sent.UserSends, mineOldest: sent.UserOldest, toAddress: sent.NumberSends,
		addressOldest: sent.NumberOldest, last: sent.UserLast}).limit(); err != nil {
		return err
	}
	id, err := qtx.InsertPhoneVerification(ctx, dbgen.InsertPhoneVerificationParams{
		UserID:    userID,
		Phone:     phone,
		CodeHash:  codes.Hash(code),
		ExpiresAt: time.Now().UTC().Add(s.ttl),
	})
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("phone.verification_started", userID,
		map[string]any{"phone": notifier.MaskDestination("sms", phone)})); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return s.withdrawUndelivered(ctx, s.q.DeletePhoneVerification, id, s.sender.Send(ctx, notifier.Message{
		Channel: "sms",
		To:      phone,
		Body:    fmt.Sprintf("Your Qeet verification code is %s", code),
	}))
}

// canSendSMS refuses a code to phone unless it is in E.164 form, a provider
// can deliver SMS, and the plan of organizationID (nil: refused) includes SMS.
func (s *Service) canSendSMS(ctx context.Context, phone string, organizationID *uuid.UUID) error {
	if !e164.MatchString(phone) {
		return errVerifyPhoneInvalid
	}
	if s.deliverable != nil && !s.deliverable("sms") {
		return ErrVerifyDeliveryUnavailable.WithMetadata(map[string]any{"channel": "sms"})
	}
	if s.plan == nil {
		return nil
	}
	refused := errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": smsFeature})
	if organizationID == nil {
		return refused
	}
	ok, err := s.plan.FeatureAllowed(ctx, *organizationID, smsFeature)
	if err != nil {
		return err
	}
	if !ok {
		return refused
	}
	return nil
}

// smsFeature is the plan feature that pays for SMS codes, MFA's and these alike.
const smsFeature = "sms_mfa"

// ConfirmPhone verifies the user's phone number with the code sent to it,
// recorded as who's; a refused code is recorded as phone.verification_failed.
func (s *Service) ConfirmPhone(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	err := s.confirmPhone(ctx, userID, code, who)
	return s.auditRefusal(ctx, "phone.verification_failed", userID, map[string]any{}, who, err)
}

func (s *Service) confirmPhone(ctx context.Context, userID uuid.UUID, code string, who Requester) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := s.q.WithTx(tx)

	row, err := newestPhoneCode(ctx, qtx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrVerifyCodeInvalid
		}
		return err
	}
	failed, err := qtx.PhoneCodeFailures(ctx, userID)
	if err != nil {
		return err
	}
	if err := chargeFailure(ctx, tx, row, code, guessBudget{failures: int(failed.Failures), oldest: failed.Oldest}); err != nil {
		return err
	}
	if err := qtx.MarkPhoneVerificationUsed(ctx, row.id); err != nil {
		return err
	}
	// Persist the verified number itself (not just the timestamp) so downstream
	// SMS/OTP has a number to use and the account isn't left "verified" with a
	// NULL phone.
	if err := qtx.SetUserVerifiedPhone(ctx, dbgen.SetUserVerifiedPhoneParams{
		Phone:  &row.value,
		UserID: userID,
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, who.event("phone.verified", userID,
		map[string]any{"phone": notifier.MaskDestination("sms", row.value), "proof": "sms_code"})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
