package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// mfaChallengeTTL bounds how long a pending second-factor login stays valid.
const mfaChallengeTTL = 10 * time.Minute

// How a challenged sign-in proved its first factor (mfa_login_challenges
// first_factor). The session it completes records the method
// "<first factor>_mfa", or the first factor alone when an enrolment was put
// off.
const (
	firstFactorPassword  = "password"
	firstFactorMagicLink = "magic_link"
	firstFactorSocial    = "social"
)

// challengeSignIn records a short-lived, single-use pending sign-in that the MFA
// step later exchanges for a session, and audits why it was challenged. claims
// are hook claims carried across the MFA step.
func (s *Service) challengeSignIn(ctx context.Context, userID, tenantID uuid.UUID, claims map[string]any, gate mfaGate, firstFactor, ip, ua string) (MFAChallenge, error) {
	var tid any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		tid = tenantID
		tenantPtr = &tenantID
	}
	var claimsArg any
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return MFAChallenge{}, err
		}
		claimsArg = raw
	}
	challenge := MFAChallenge{MFARequired: true, Methods: methodsOf(gate.factors), Factors: gate.factors}
	if gate.enrollment() {
		challenge.Methods = []string{"totp"}
		challenge.Factors = []LoginFactor{}
		challenge.EnrollmentRequired = true
		challenge.EnrollmentDueAt = gate.req.graceUntil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return MFAChallenge{}, err
	}
	defer tx.Rollback(ctx)
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.mfa_login_challenges (user_id, tenant_id, expires_at, claims, enrollment, first_factor)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
	`, userID, tid, time.Now().UTC().Add(mfaChallengeTTL), claimsArg, challenge.EnrollmentRequired, firstFactor).Scan(&id); err != nil {
		return MFAChallenge{}, err
	}
	meta := map[string]any{"reason": gate.reason(), "enrollment": challenge.EnrollmentRequired, "methods": challenge.Methods,
		"first_factor": firstFactor}
	if challenge.EnrollmentDueAt != nil {
		meta["grace_until"] = challenge.EnrollmentDueAt
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       "auth.mfa_challenged",
		ResourceType: "user",
		ResourceID:   &userID,
		IP:           ip,
		UserAgent:    ua,
		Metadata:     meta,
	}); err != nil {
		return MFAChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return MFAChallenge{}, err
	}
	challenge.MFAToken = id.String()
	return challenge, nil
}

// metChallenge is a sign-in challenge met and consumed.
type metChallenge struct {
	userID uuid.UUID
	// tenantID is uuid.Nil for a tenant-less challenge.
	tenantID uuid.UUID
	claims   map[string]any
	// recoveryCodes are minted when the challenge was met by setting up an
	// authenticator app; shown once.
	recoveryCodes []string
	// deferred: an enrolment challenge skipped in the grace period — no
	// factor was met.
	deferred bool
	// firstFactor is how the sign-in proved its first factor.
	firstFactor string
	// riskVerified: a risk challenge met by the code to the verified email —
	// confirmed, but no second factor was met.
	riskVerified bool
	// stepUpMethod is the second factor that met the challenge ("" when none
	// did): the session the sign-in opens starts stepped up by it.
	stepUpMethod string
}

// method is the sign-in method recorded on the session.
func (m metChallenge) method() string {
	switch {
	case m.deferred:
		return m.firstFactor
	case m.riskVerified:
		return m.firstFactor + "_email_confirmed"
	}
	return m.firstFactor + "_mfa"
}

// verifyAndConsumeMFAChallenge checks a pending MFA challenge and its proof. A
// valid proof consumes the challenge and returns the user, tenant and claims. A
// wrong proof is recorded as a failed sign-in and leaves the challenge for a
// retry.
func (s *Service) verifyAndConsumeMFAChallenge(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (metChallenge, error) {
	if s.mfa == nil {
		return metChallenge{}, errs.ErrNotImplemented
	}
	id, err := uuid.Parse(mfaToken)
	if err != nil {
		return metChallenge{}, errs.ErrAuthSessionInvalid
	}
	var userID uuid.UUID
	var tenantID *uuid.UUID
	var expiresAt time.Time
	var rawClaims []byte
	var challengeFailures int16
	var passkeySession, pushChallenge *uuid.UUID
	var enrollment, enrollmentStarted, riskEmail bool
	var firstFactor string
	var emailCodeHash *string
	var emailCodeExpires *time.Time
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return metChallenge{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, expires_at, claims, failed_attempts, passkey_session_id, push_challenge_id,
		       enrollment, enrollment_started, first_factor, risk_email, email_code_hash, email_code_expires_at
		FROM auth.mfa_login_challenges
		WHERE id = $1
		FOR UPDATE
	`, id).Scan(&userID, &tenantID, &expiresAt, &rawClaims, &challengeFailures, &passkeySession, &pushChallenge,
		&enrollment, &enrollmentStarted, &firstFactor, &riskEmail, &emailCodeHash, &emailCodeExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return metChallenge{}, errs.ErrAuthMFAChallengeExpired
	}
	if err != nil {
		return metChallenge{}, err
	}
	if time.Now().After(expiresAt) {
		if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
			return metChallenge{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return metChallenge{}, err
		}
		return metChallenge{}, errs.ErrAuthMFAChallengeExpired
	}
	met := metChallenge{userID: userID, firstFactor: firstFactor}
	if tenantID != nil {
		met.tenantID = *tenantID
	}
	if len(rawClaims) > 0 {
		_ = json.Unmarshal(rawClaims, &met.claims)
	}
	// What the challenge cannot be met with is refused before an attempt is
	// counted.
	switch {
	case (enrollment || riskEmail) && (proof.Passkey != nil || proof.Push):
		return metChallenge{}, errNotAFactorChallenge
	case riskEmail && proof.Skip:
		return metChallenge{}, errs.ErrBadRequest.WithDetail("This sign-in needs confirming; it cannot be skipped.")
	case enrollment && proof.Skip:
		return s.deferEnrollment(ctx, tx, id, met)
	case !enrollment && proof.Skip:
		return metChallenge{}, errs.ErrBadRequest.WithDetail("This sign-in needs a second factor; it cannot be skipped.")
	case enrollment && !enrollmentStarted:
		return metChallenge{}, errs.ErrMFAEnrollNotStarted
	case enrollment:
		if err := s.stillWithoutFactor(ctx, tx, userID); err != nil {
			return metChallenge{}, err
		}
	}
	// An unanswered or expired push request is not a wrong answer: it costs
	// no attempt, and the challenge stays as it is.
	if proof.Push && pushChallenge != nil {
		status, err := s.mfa.LoginPushStatusTx(ctx, tx, userID, *pushChallenge)
		if err != nil {
			return metChallenge{}, err
		}
		switch status {
		case "pending":
			return metChallenge{}, errs.ErrMFAPushPending
		case "expired":
			return metChallenge{}, errs.ErrMFAPushChallengeExpired
		}
	}
	accountRemaining, err := reserveLoginMFAAttempt(ctx, tx, userID)
	if err != nil {
		return metChallenge{}, err
	}
	var ok bool
	if riskEmail {
		// Confirmed by the latest code sent to the verified email; no second
		// factor is met, so the session starts with no step-up.
		ok = emailCodeHash != nil && emailCodeExpires != nil && time.Now().Before(*emailCodeExpires) &&
			subtle.ConstantTimeCompare([]byte(*emailCodeHash), []byte(codes.Hash(strings.TrimSpace(proof.Code)))) == 1
		met.riskVerified = ok
	} else if enrollment {
		met.recoveryCodes, ok, err = s.mfa.ConfirmLoginEnrollment(ctx, tx, userID, proof.Code)
		if ok {
			met.stepUpMethod = "totp"
		}
	} else {
		met.stepUpMethod, err = s.verifyMFAProof(ctx, tx, userID, passkeySession, pushChallenge, proof)
		ok = met.stepUpMethod != ""
	}
	if err != nil {
		return metChallenge{}, err
	}
	if !ok {
		next := challengeFailures + 1
		remaining := maxMFALoginAttempts - int(next)
		if next >= maxMFALoginAttempts {
			if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
				return metChallenge{}, err
			}
		} else if _, err := tx.Exec(ctx, `
			UPDATE auth.mfa_login_challenges SET failed_attempts = $2 WHERE id = $1
		`, id, next); err != nil {
			return metChallenge{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return metChallenge{}, err
		}
		failure := SignInFailure{UserID: userID, Method: "mfa", Reason: FailureCodeInvalid, IP: ip, UserAgent: ua,
			Metadata: map[string]any{"proof": metProofKind(proof, enrollment, riskEmail), "first_factor": firstFactor,
				"remaining_attempts": max(min(remaining, accountRemaining), 0)}}
		if tenantID != nil {
			failure.TenantID = *tenantID
		}
		s.RecordSignInFailure(ctx, failure)
		if remaining <= 0 || accountRemaining <= 0 {
			return metChallenge{}, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
		}
		if accountRemaining < remaining {
			remaining = accountRemaining
		}
		return metChallenge{}, errs.ErrMFACodeInvalid.WithMetadata(map[string]any{"remaining_attempts": remaining})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
		return metChallenge{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = 'login'`, userID); err != nil {
		return metChallenge{}, err
	}
	if enrollment {
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID:     tenantID,
			ActorUserID:  &userID,
			ActorType:    "user",
			Action:       "mfa.totp_enrolled",
			ResourceType: "user",
			ResourceID:   &userID,
			Metadata:     map[string]any{"recovery_codes_minted": len(met.recoveryCodes), "via": "sign_in"},
		}); err != nil {
			return metChallenge{}, err
		}
	}
	// The sign-in met its second factor: recorded for both sign-in flows, so
	// the trail says which first factor it followed.
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       metAction(riskEmail),
		ResourceType: "user",
		ResourceID:   &userID,
		Metadata:     map[string]any{"first_factor": firstFactor, "proof": metProofKind(proof, enrollment, riskEmail)},
	}); err != nil {
		return metChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return metChallenge{}, err
	}
	return met, nil
}

// deferEnrollment consumes an enrolment challenge skipped while the grace
// period runs, and audits it. Refused (ErrMFAEnrollmentRequired) once the
// account must set up a factor now; refusing costs no attempt.
func (s *Service) deferEnrollment(ctx context.Context, tx pgx.Tx, id uuid.UUID, met metChallenge) (metChallenge, error) {
	graceUntil, err := s.mayDeferEnrollment(ctx, tx, met.userID, met.tenantID)
	if err != nil {
		return metChallenge{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_login_challenges WHERE id = $1`, id); err != nil {
		return metChallenge{}, err
	}
	var tenantPtr *uuid.UUID
	if met.tenantID != uuid.Nil {
		tenantPtr = &met.tenantID
	}
	meta := map[string]any{"first_factor": met.firstFactor}
	if graceUntil != nil {
		meta["grace_until"] = graceUntil
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &met.userID,
		ActorType:    "user",
		Action:       "auth.mfa_enrollment_deferred",
		ResourceType: "user",
		ResourceID:   &met.userID,
		Metadata:     meta,
	}); err != nil {
		return metChallenge{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return metChallenge{}, err
	}
	met.deferred = true
	return met, nil
}

const (
	maxMFALoginAttempts   = 5
	mfaLoginAttemptWindow = 10 * time.Minute
)

func reserveLoginMFAAttempt(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.mfa_attempt_budgets (user_id, purpose)
		VALUES ($1, 'login')
		ON CONFLICT DO NOTHING
	`, userID); err != nil {
		return 0, err
	}
	var failed int16
	var windowStarted time.Time
	var lockedUntil pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `
		SELECT failed_attempts, window_started_at, locked_until
		FROM auth.mfa_attempt_budgets
		WHERE user_id = $1 AND purpose = 'login'
		FOR UPDATE
	`, userID).Scan(&failed, &windowStarted, &lockedUntil); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		return 0, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaLoginAttemptWindow || (lockedUntil.Valid && !now.Before(lockedUntil.Time)) {
		failed = 0
		windowStarted = now
	}
	next := failed + 1
	var lock any
	if next >= maxMFALoginAttempts {
		lock = now.Add(mfaLoginAttemptWindow)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET failed_attempts = $2, window_started_at = $3, locked_until = $4
		WHERE user_id = $1 AND purpose = 'login'
	`, userID, next, windowStarted, lock); err != nil {
		return 0, err
	}
	return maxMFALoginAttempts - int(next), nil
}

// CompleteMFALogin verifies the second-factor code for a pending token-flow
// login and, on success, issues the token pair.
func (s *Service) CompleteMFALogin(ctx context.Context, mfaToken, code, ip, ua string) (*TokenPair, error) {
	pair, _, err := s.CompleteMFALoginWith(ctx, mfaToken, MFAProof{Code: code}, ip, ua)
	return pair, err
}

// CompleteMFALoginWith is CompleteMFALogin met by any proof: a code, a
// passkey assertion, an approved push, or — for an enrolment challenge — the
// code confirming the authenticator app set up for it (whose new recovery
// codes it also returns) or a skip in the grace period.
func (s *Service) CompleteMFALoginWith(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (*TokenPair, []string, error) {
	met, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, proof, ip, ua)
	if err != nil {
		return nil, nil, err
	}
	if err := s.refuseSignIn(ctx, met.userID, met.tenantID, met.method(), ip, ua); err != nil {
		return nil, nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, met.userID, met.tenantID, ip, ua, met.method(), met.claims, nil, time.Time{})
	if err != nil {
		return nil, nil, s.signInFailed(ctx, tx, err)
	}
	// The second factor this sign-in met steps up the session it opens, and
	// only that one: no other session of the person's gains anything from it.
	if met.stepUpMethod != "" {
		if err := s.mfa.RecordVerification(ctx, tx, met.userID, pair.SessionID, met.stepUpMethod); err != nil {
			return nil, nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	s.recordSignIn(ctx, met.userID, met.tenantID, ua, httpx.GeoCountry(ctx))
	return pair, met.recoveryCodes, nil
}

// MFALoginSession is a hosted-login challenge met: the SSO session cookie
// value to write via SetLoginSessionCookie, and the recovery codes minted
// when the challenge was met by setting up an authenticator app.
type MFALoginSession struct {
	UserID uuid.UUID
	// TenantID is uuid.Nil when tenant-less.
	TenantID      uuid.UUID
	RawCookie     string
	RecoveryCodes []string
	// Deferred: an enrolment challenge skipped in the grace period. No
	// factor was met, so the device must not be remembered.
	Deferred bool
}

// CompleteMFALoginSession verifies the second-factor code for a pending
// hosted-login challenge and returns the user ID, the tenant ID (uuid.Nil if
// none) and the SSO session cookie value.
func (s *Service) CompleteMFALoginSession(ctx context.Context, mfaToken, code, ip, ua string) (uuid.UUID, uuid.UUID, string, error) {
	res, err := s.CompleteMFALoginSessionWith(ctx, mfaToken, MFAProof{Code: code}, ip, ua)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	return res.UserID, res.TenantID, res.RawCookie, nil
}

// CompleteMFALoginSessionWith is CompleteMFALoginSession met by any proof
// (see CompleteMFALoginWith).
func (s *Service) CompleteMFALoginSessionWith(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (*MFALoginSession, error) {
	// Any hook claims stashed on the challenge are discarded here — see the
	// note in BeginLoginSession on why this cookie flow doesn't carry them.
	met, err := s.verifyAndConsumeMFAChallenge(ctx, mfaToken, proof, ip, ua)
	if err != nil {
		return nil, err
	}
	factor := ""
	if !met.deferred && !met.riskVerified {
		factor = secondFactorMFA
	}
	raw, err := s.createLoginSession(ctx, met.userID, ip, ua, factor)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, met.userID, met.tenantID, ua, httpx.GeoCountry(ctx))
	// A confirmed risky sign-in met no factor either, so earns no remembered device.
	return &MFALoginSession{UserID: met.userID, TenantID: met.tenantID, RawCookie: raw,
		RecoveryCodes: met.recoveryCodes, Deferred: met.deferred || met.riskVerified}, nil
}
