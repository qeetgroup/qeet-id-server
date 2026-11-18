package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Every sign-in that proves its first factor is risk-assessed against earlier
// ones that got their session; only those are recorded. A risky sign-in can't
// skip MFA on a remembered device, and one without a second factor confirms a
// code sent to the verified email (a magic link has already proved it).

// nextStep is what a sign-in that proved its first factor does next.
type nextStep int

const (
	stepSession   nextStep = iota // issue the session
	stepChallenge                 // ask for a held factor, or set up a required one
	stepRiskEmail                 // confirm with a code sent to the verified email
)

// nextSignInStep decides a sign-in's next step. trustedToken is the request's
// remembered-device cookie ("" where there is none, as on the API). A sign-in
// that goes on to stepSession is recorded, by recordSignIn, once its session
// is issued.
func (s *Service) nextSignInStep(ctx context.Context, userID, organizationID uuid.UUID, gate mfaGate, firstFactor,
	trustedToken, ip, ua, country string) nextStep {
	risky := s.riskAssessor != nil && s.riskAssessor.ShouldForceMFA(ctx, organizationID, userID, ip, ua, country)
	switch {
	case gate.enrollment():
		return stepChallenge
	case gate.challenged():
		if !risky && s.trustedDeviceSkips(ctx, userID, organizationID, trustedToken) {
			return stepSession
		}
		return stepChallenge
	case risky && firstFactor != firstFactorMagicLink:
		return stepRiskEmail
	}
	return stepSession
}

// recordSignIn records, for later risk assessments, a sign-in whose session
// (or hosted-login session) has been issued.
func (s *Service) recordSignIn(ctx context.Context, userID, organizationID uuid.UUID, ua, country string) {
	if s.riskAssessor != nil {
		s.riskAssessor.RecordSignIn(ctx, organizationID, userID, ua, country)
	}
}

// trustedDeviceSkips reports whether a remembered device may skip the second
// factor: the organization allows it and the request carries a live
// remembered-device token of the person's, for that organization. Any failure
// or missing piece is false — the safe default is always to ask.
func (s *Service) trustedDeviceSkips(ctx context.Context, userID, organizationID uuid.UUID, trustedToken string) bool {
	if s.devicePolicy == nil || trustedToken == "" {
		return false
	}
	enabled, err := s.devicePolicy.RememberDeviceEnabled(ctx, organizationID)
	if err != nil || !enabled {
		return false
	}
	return s.IsTrustedDevice(ctx, userID, organizationID, trustedToken)
}

// riskEmailChallenge records a challenge met by a code sent to the verified
// email, for a risky sign-in with no second factor, and audits it. It returns
// ErrAuthRiskVerificationUnavailable when the account has no verified email.
func (s *Service) riskEmailChallenge(ctx context.Context, userID, organizationID uuid.UUID, claims map[string]any,
	firstFactor, ip, ua string) (MFAChallenge, error) {
	account, err := s.q.AccountEmailVerified(ctx, userID)
	if err != nil {
		return MFAChallenge{}, err
	}
	organizationPtr, by := orNil(organizationID), asUser(userID, ip, ua)
	if !account.Verified || account.Email == "" || s.sender == nil {
		_ = audit.RecordAlone(ctx, s.pool, by.EventIn(organizationPtr, "auth.sign_in_refused", "user", userID,
			map[string]any{"reason": "risk_unverifiable", "first_factor": firstFactor}))
		return MFAChallenge{}, ErrRiskVerificationUnavailable
	}
	var claimsArg []byte
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
	id, err := s.q.WithTx(tx).InsertRiskEmailChallenge(ctx, dbgen.InsertRiskEmailChallengeParams{
		UserID: userID, OrganizationID: organizationPtr, ExpiresAt: time.Now().UTC().Add(mfaChallengeTTL),
		Claims: claimsArg, FirstFactor: firstFactor,
	})
	if err != nil {
		return MFAChallenge{}, err
	}
	factor := LoginFactor{Type: "email", ID: &id, Destination: notifier.MaskDestination("email", account.Email)}
	challenge := MFAChallenge{MFARequired: true, Methods: []string{"email"}, Factors: []LoginFactor{factor}}
	if err := audit.Record(ctx, tx, by.EventIn(organizationPtr, "auth.mfa_challenged", "user", userID,
		map[string]any{"reason": mfaReasonRisk, "enrollment": false, "methods": challenge.Methods, "first_factor": firstFactor})); err != nil {
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

// riskEmailCode is a risk challenge's code and the verified email it goes to.
type riskEmailCode struct {
	email, code string
}

// newRiskEmailCode issues, inside the challenge transaction, the code that
// meets a risk challenge: it replaces any earlier one, at most one every
// riskEmailResendAfter. sendRiskEmailCode sends it once tx has committed.
func (s *Service) newRiskEmailCode(ctx context.Context, tx pgx.Tx, id uuid.UUID, c pendingMFAChallenge) (riskEmailCode, error) {
	if c.emailCodeSentAt != nil {
		if wait := riskEmailResendAfter - time.Since(*c.emailCodeSentAt); wait > 0 {
			return riskEmailCode{}, errs.ErrMFACodeSendLimited.WithMetadata(map[string]any{"retry_after": int(wait.Round(time.Second).Seconds()) + 1})
		}
	}
	q := s.q.WithTx(tx)
	var out riskEmailCode
	var err error
	if out.email, err = q.VerifiedAccountEmail(ctx, c.userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return riskEmailCode{}, ErrRiskVerificationUnavailable
		}
		return riskEmailCode{}, err
	}
	if out.code, err = codes.Numeric(6); err != nil {
		return riskEmailCode{}, err
	}
	if err := q.IssueRiskEmailCode(ctx, dbgen.IssueRiskEmailCodeParams{
		ID: id, EmailCodeHash: new(codes.Hash(out.code)), EmailCodeExpiresAt: new(time.Now().UTC().Add(riskEmailCodeTTL)),
	}); err != nil {
		return riskEmailCode{}, err
	}
	return out, nil
}

// sendRiskEmailCode emails the code newRiskEmailCode issued for challenge id,
// loaded as c. If it fails to go, the challenge's earlier code, pacing and
// count are put back, and the failure is ErrMFADeliveryFailed.
func (s *Service) sendRiskEmailCode(ctx context.Context, id uuid.UUID, c pendingMFAChallenge, code riskEmailCode) error {
	err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      code.email,
		Subject: "Confirm it's you signing in",
		Body: fmt.Sprintf("Someone is signing in to your account from a device or place we don't recognise. "+
			"If it's you, enter this code: %s. It expires in %s. If it isn't you, change your password.", code.code, riskEmailCodeTTL),
	})
	if err == nil {
		return nil
	}
	// On a context of its own, so a send that failed as ctx ended is undone too.
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if uerr := s.q.WithdrawRiskEmailCode(uctx, dbgen.WithdrawRiskEmailCodeParams{
		ID: id, SentHash: new(codes.Hash(code.code)),
		EmailCodeHash: c.emailCodeHash, EmailCodeExpiresAt: c.emailCodeExpiresAt, EmailCodeSentAt: c.emailCodeSentAt,
	}); uerr != nil {
		slog.Warn("undelivered risk email code not withdrawn", "err", uerr)
	}
	return errs.ErrMFADeliveryFailed.Wrap(err)
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
