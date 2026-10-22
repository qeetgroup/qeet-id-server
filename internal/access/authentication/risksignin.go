package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Every sign-in that proves its first factor is risk-assessed once, which also
// records its country and device for the next comparison. A risky sign-in can't
// skip MFA on a remembered device, and one without a second factor is confirmed
// by a code sent to the verified email (a magic link has already proved it).

// nextStep is what a sign-in that proved its first factor does next.
type nextStep int

const (
	stepSession   nextStep = iota // issue the session
	stepChallenge                 // ask for a held factor, or set up a required one
	stepRiskEmail                 // confirm with a code sent to the verified email
)

// nextSignInStep decides a sign-in's next step. trustedToken is the request's
// remembered-device cookie ("" where there is none, as on the API).
func (s *Service) nextSignInStep(ctx context.Context, userID, tenantID uuid.UUID, gate mfaGate, firstFactor,
	trustedToken, ip, ua, country string) nextStep {
	risky := s.riskAssessor != nil && s.riskAssessor.ShouldForceMFA(ctx, tenantID, userID, ip, ua, country)
	switch {
	case gate.enrollment():
		return stepChallenge
	case gate.challenged():
		if !risky && s.trustedDeviceSkips(ctx, userID, tenantID, trustedToken) {
			return stepSession
		}
		return stepChallenge
	case risky && firstFactor != firstFactorMagicLink:
		return stepRiskEmail
	}
	return stepSession
}

// trustedDeviceSkips reports whether a remembered device may skip the second
// factor: the organisation allows it and the request carries a live
// remembered-device token of the person's, for that organisation. Any failure
// or missing piece is false — the safe default is always to ask.
func (s *Service) trustedDeviceSkips(ctx context.Context, userID, tenantID uuid.UUID, trustedToken string) bool {
	if s.devicePolicy == nil || trustedToken == "" {
		return false
	}
	enabled, err := s.devicePolicy.RememberDeviceEnabled(ctx, tenantID)
	if err != nil || !enabled {
		return false
	}
	return s.IsTrustedDevice(ctx, userID, tenantID, trustedToken)
}

// riskEmailChallenge records a challenge met by a code sent to the verified
// email, for a risky sign-in with no second factor, and audits it. It returns
// ErrAuthRiskVerificationUnavailable when the account has no verified email.
func (s *Service) riskEmailChallenge(ctx context.Context, userID, tenantID uuid.UUID, claims map[string]any,
	firstFactor, ip, ua string) (MFAChallenge, error) {
	var email string
	var verified bool
	if err := s.pool.QueryRow(ctx, `SELECT email, email_verified_at IS NOT NULL FROM "user".users WHERE id = $1`, userID).
		Scan(&email, &verified); err != nil {
		return MFAChallenge{}, err
	}
	var tenantPtr *uuid.UUID
	var tid any
	if tenantID != uuid.Nil {
		tenantPtr, tid = &tenantID, tenantID
	}
	if !verified || email == "" || s.sender == nil {
		_ = s.auditTx(ctx, audit.Event{TenantID: tenantPtr, ActorUserID: &userID, ActorType: "user",
			Action: "auth.sign_in_refused", ResourceType: "user", ResourceID: &userID, IP: ip, UserAgent: ua,
			Metadata: map[string]any{"reason": "risk_unverifiable", "first_factor": firstFactor}})
		return MFAChallenge{}, errs.ErrAuthRiskVerificationUnavailable
	}
	var claimsArg any
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return MFAChallenge{}, err
		}
		claimsArg = raw
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MFAChallenge{}, err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.mfa_login_challenges (user_id, tenant_id, expires_at, claims, first_factor, risk_email)
		VALUES ($1, $2, $3, $4, $5, TRUE) RETURNING id
	`, userID, tid, time.Now().UTC().Add(mfaChallengeTTL), claimsArg, firstFactor).Scan(&id); err != nil {
		return MFAChallenge{}, err
	}
	factor := LoginFactor{Type: "email", ID: &id, Destination: maskEmail(email)}
	challenge := MFAChallenge{MFARequired: true, Methods: []string{"email"}, Factors: []LoginFactor{factor}}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: tenantPtr, ActorUserID: &userID, ActorType: "user",
		Action: "auth.mfa_challenged", ResourceType: "user", ResourceID: &userID, IP: ip, UserAgent: ua,
		Metadata: map[string]any{"reason": mfaReasonRisk, "enrollment": false, "methods": challenge.Methods,
			"first_factor": firstFactor},
	}); err != nil {
		return MFAChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MFAChallenge{}, err
	}
	challenge.MFAToken = id.String()
	return challenge, nil
}

// mfaReasonRisk: a sign-in challenged because it was assessed as risky and
// its person holds no second factor.
const mfaReasonRisk = "risk"

// riskEmailResendAfter paces codes for one risk challenge.
const riskEmailResendAfter = 30 * time.Second

// riskEmailCodeTTL is how long a risk challenge's emailed code works.
const riskEmailCodeTTL = 10 * time.Minute

// sendRiskEmailCode sends the code that meets a risk challenge to the
// person's verified email, inside the challenge transaction: the latest code
// replaces any earlier one, at most one every riskEmailResendAfter.
func (s *Service) sendRiskEmailCode(ctx context.Context, tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) error {
	if c.emailCodeSentAt != nil {
		if wait := riskEmailResendAfter - time.Since(*c.emailCodeSentAt); wait > 0 {
			return errs.ErrMFACodeSendLimited.WithMetadata(map[string]any{"retry_after": int(wait.Round(time.Second).Seconds()) + 1})
		}
	}
	var email string
	if err := tx.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1 AND email_verified_at IS NOT NULL`, c.userID).
		Scan(&email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errs.ErrAuthRiskVerificationUnavailable
		}
		return err
	}
	code, err := codes.Numeric(6)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_login_challenges
		SET email_code_hash = $2, email_code_expires_at = $3, email_code_sent_at = NOW(), codes_sent = codes_sent + 1
		WHERE id = $1
	`, id, codes.Hash(code), time.Now().UTC().Add(riskEmailCodeTTL)); err != nil {
		return err
	}
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Confirm it's you signing in",
		Body: fmt.Sprintf("Someone is signing in to your account from a device or place we don't recognise. "+
			"If it's you, enter this code: %s. It expires in %s. If it isn't you, change your password.", code, riskEmailCodeTTL),
	}); err != nil {
		return errs.ErrMFADeliveryFailed.Wrap(err)
	}
	return nil
}

// auditTx records one audit event in its own transaction.
func (s *Service) auditTx(ctx context.Context, e audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// maskEmail keeps the first character of the address's local part and its
// domain: "j***@example.com".
func maskEmail(email string) string {
	for i := range len(email) {
		if email[i] == '@' {
			if i <= 1 {
				return email
			}
			return email[:1] + "***" + email[i:]
		}
	}
	return email
}

// metProofKind names how a met challenge was met, as audited.
func metProofKind(p MFAProof, enrollment, riskEmail bool) string {
	if riskEmail {
		return "email_confirmation"
	}
	return p.kind(enrollment)
}

// metAction is the audit action for a met challenge: a risk challenge
// confirms the sign-in without a second factor.
func metAction(riskEmail bool) string {
	if riskEmail {
		return "auth.sign_in_confirmed"
	}
	return "auth.mfa_verified"
}
