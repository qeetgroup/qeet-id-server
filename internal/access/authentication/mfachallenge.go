package authentication

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/emailtmpl"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
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
func (s *Service) challengeSignIn(ctx context.Context, userID, organizationID uuid.UUID, claims map[string]any, gate mfaGate, firstFactor, ip, ua string) (MFAChallenge, error) {
	organizationPtr := orNil(organizationID)
	var claimsArg []byte
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
	id, err := s.q.WithTx(tx).InsertMFAChallenge(ctx, dbgen.InsertMFAChallengeParams{
		UserID: userID, OrganizationID: organizationPtr, ExpiresAt: time.Now().UTC().Add(mfaChallengeTTL),
		Claims: claimsArg, Enrollment: challenge.EnrollmentRequired, FirstFactor: firstFactor,
	})
	if err != nil {
		return MFAChallenge{}, err
	}
	meta := map[string]any{"reason": gate.reason(), "enrollment": challenge.EnrollmentRequired, "methods": challenge.Methods,
		"first_factor": firstFactor}
	if challenge.EnrollmentDueAt != nil {
		meta["grace_until"] = challenge.EnrollmentDueAt
	}
	if err := audit.Record(ctx, tx, asUser(userID, ip, ua).EventIn(organizationPtr, "auth.mfa_challenged", "user", userID, meta)); err != nil {
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
	// organizationID is uuid.Nil for an organization-less challenge.
	organizationID uuid.UUID
	claims         map[string]any
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
// valid proof consumes the challenge and returns the user, organization and claims. A
// wrong proof is recorded as a failed sign-in and leaves the challenge for a
// retry.
func (s *Service) verifyAndConsumeMFAChallenge(ctx context.Context, mfaToken string, proof MFAProof, ip, ua string) (metChallenge, error) {
	id, err := uuid.Parse(mfaToken)
	if err != nil {
		return metChallenge{}, ErrSessionInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return metChallenge{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := liveChallengeForProof(ctx, tx, q, id)
	if err != nil {
		return metChallenge{}, err
	}
	met := metChallenge{userID: row.UserID, firstFactor: row.FirstFactor}
	if row.OrganizationID != nil {
		met.organizationID = *row.OrganizationID
	}
	if len(row.Claims) > 0 {
		_ = json.Unmarshal(row.Claims, &met.claims)
	}
	deferNow, err := s.refuseUnmeetable(ctx, tx, row, proof)
	if err != nil {
		return metChallenge{}, err
	}
	if deferNow {
		return s.deferEnrollment(ctx, tx, id, met)
	}
	accountRemaining, err := reserveLoginMFAAttempt(ctx, tx, row.UserID)
	if err != nil {
		return metChallenge{}, err
	}
	streak, err := dbgen.New(tx).CountMFAAttempt(ctx, row.UserID)
	if err != nil {
		return metChallenge{}, err
	}
	if streak.Locked {
		return metChallenge{}, errs.ErrMFALocked
	}
	ok, err := s.checkProof(ctx, tx, row, &met, proof)
	if err != nil {
		return metChallenge{}, err
	}
	if !ok {
		return metChallenge{}, s.failProof(ctx, tx, q, id, row, proof, streak, accountRemaining, ip, ua)
	}
	if err := consumeChallenge(ctx, tx, q, id, row, met, proof); err != nil {
		return metChallenge{}, err
	}
	return met, nil
}

// liveChallengeForProof reads, locked through tx, the challenge id names for
// its proof to be checked: ErrAuthMFAChallengeExpired for an unknown one, and
// for an expired one, which is removed for good (tx commits).
func liveChallengeForProof(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, id uuid.UUID) (dbgen.LockMFAChallengeForProofRow, error) {
	row, err := q.LockMFAChallengeForProof(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return row, errs.ErrAuthMFAChallengeExpired
	}
	if err != nil {
		return row, err
	}
	if time.Now().After(row.ExpiresAt) {
		if err := q.DeleteMFALoginChallenge(ctx, id); err != nil {
			return row, err
		}
		if err := tx.Commit(ctx); err != nil {
			return row, err
		}
		return row, errs.ErrAuthMFAChallengeExpired
	}
	return row, nil
}

// refuseUnmeetable refuses, before an attempt is counted, a proof the
// challenge c cannot be met with, and an unanswered or expired push request,
// which is not a wrong answer either: the challenge stays as it is. deferNow
// reports a skipped enrolment, which defers it instead.
func (s *Service) refuseUnmeetable(ctx context.Context, tx pgx.Tx, c dbgen.LockMFAChallengeForProofRow, proof MFAProof) (deferNow bool, err error) {
	switch {
	case (c.Enrollment || c.RiskEmail) && (proof.Passkey != nil || proof.Push):
		return false, errNotAFactorChallenge
	case c.RiskEmail && proof.Skip:
		return false, errs.ErrBadRequest.WithDetail("This sign-in needs confirming; it cannot be skipped.")
	case c.Enrollment && proof.Skip:
		return true, nil
	case !c.Enrollment && proof.Skip:
		return false, errs.ErrBadRequest.WithDetail("This sign-in needs a second factor; it cannot be skipped.")
	case c.Enrollment && !c.EnrollmentStarted:
		return false, errs.ErrMFAEnrollNotStarted
	case c.Enrollment:
		if err := s.stillWithoutFactor(ctx, tx, c.UserID); err != nil {
			return false, err
		}
	}
	if proof.Push && c.PushChallengeID != nil {
		status, err := s.mfa.LoginPushStatusTx(ctx, tx, c.UserID, *c.PushChallengeID)
		if err != nil {
			return false, err
		}
		switch status {
		case "pending":
			return false, errs.ErrMFAPushPending
		case "expired":
			return false, errs.ErrMFAPushChallengeExpired
		}
	}
	return false, nil
}

// checkProof reports whether proof meets challenge c, inside tx, noting on met what it met: a risk
// challenge by the latest code sent to the verified email (meeting no second factor, so no step-up),
// an enrolment by a code from the app set up for it (minting recovery codes), any other by one of
// the person's factors.
func (s *Service) checkProof(ctx context.Context, tx pgx.Tx, c dbgen.LockMFAChallengeForProofRow, met *metChallenge, proof MFAProof) (bool, error) {
	switch {
	case c.RiskEmail:
		ok := c.EmailCodeHash != nil && c.EmailCodeExpiresAt != nil && time.Now().Before(*c.EmailCodeExpiresAt) &&
			subtle.ConstantTimeCompare([]byte(*c.EmailCodeHash), []byte(codes.Hash(strings.TrimSpace(proof.Code)))) == 1
		met.riskVerified = ok
		return ok, nil
	case c.Enrollment:
		var ok bool
		var err error
		met.recoveryCodes, ok, err = s.mfa.ConfirmLoginEnrollment(ctx, tx, c.UserID, proof.Code)
		if ok {
			met.stepUpMethod = "totp"
		}
		return ok, err
	default:
		var err error
		met.stepUpMethod, err = s.verifyMFAProof(ctx, tx, c.UserID, c.PasskeySessionID, c.PushChallengeID, proof)
		return met.stepUpMethod != "", err
	}
}

// failProof records a wrong proof of challenge id and returns the answer: it counts against the
// challenge (removed at its last attempt) and, after a long run of wrong answers (streak), locks
// second-factor sign-in, then commits tx and records the failed sign-in. accountRemaining is what is
// left of the account's own attempts.
func (s *Service) failProof(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, id uuid.UUID, c dbgen.LockMFAChallengeForProofRow,
	proof MFAProof, streak dbgen.CountMFAAttemptRow, accountRemaining int, ip, ua string) error {
	lockNow := streak.Failures >= maxMFAFailureStreak
	if lockNow {
		if err := s.lockMFASignIn(ctx, tx, c.UserID, c.OrganizationID, int(streak.Failures)); err != nil {
			return err
		}
	}
	next := c.FailedAttempts + 1
	remaining := maxMFALoginAttempts - int(next)
	if next >= maxMFALoginAttempts || lockNow {
		if err := q.DeleteMFALoginChallenge(ctx, id); err != nil {
			return err
		}
	} else if err := q.CountMFAChallengeFailure(ctx, dbgen.CountMFAChallengeFailureParams{ID: id, FailedAttempts: next}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	failure := SignInFailure{UserID: c.UserID, Method: "mfa", Reason: FailureCodeInvalid, Actor: audit.Actor{IP: ip, UserAgent: ua},
		Metadata: map[string]any{"proof": metProofKind(proof, c.Enrollment, c.RiskEmail), "first_factor": c.FirstFactor,
			"remaining_attempts": max(min(remaining, accountRemaining), 0)}}
	if c.OrganizationID != nil {
		failure.OrganizationID = *c.OrganizationID
	}
	s.RecordSignInFailure(ctx, failure)
	if lockNow {
		s.noticeMFALocked(ctx, c.UserID)
		return errs.ErrMFALocked
	}
	if remaining <= 0 || accountRemaining <= 0 {
		return errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if accountRemaining < remaining {
		remaining = accountRemaining
	}
	return errs.ErrMFACodeInvalid.WithMetadata(map[string]any{"remaining_attempts": remaining})
}

// consumeChallenge uses up challenge id met as met by proof: it is removed with
// the account's attempt budget and run of wrong answers, the sign-in's second
// step is audited (and an app set up for an enrolment), and tx commits.
func consumeChallenge(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, id uuid.UUID, c dbgen.LockMFAChallengeForProofRow,
	met metChallenge, proof MFAProof) error {
	if err := q.DeleteMFALoginChallenge(ctx, id); err != nil {
		return err
	}
	if err := q.ClearLoginAttemptBudget(ctx, c.UserID); err != nil {
		return err
	}
	if err := q.EndMFAFailureStreak(ctx, c.UserID); err != nil {
		return err
	}
	by := audit.Actor{UserID: &c.UserID, Type: "user"}
	if c.Enrollment {
		if err := audit.Record(ctx, tx, by.EventIn(c.OrganizationID, "mfa.totp_enrolled", "user", c.UserID,
			map[string]any{"recovery_codes_minted": len(met.recoveryCodes), "via": "sign_in"})); err != nil {
			return err
		}
	}
	// The sign-in met its second factor: recorded for both sign-in flows, so
	// the trail says which first factor it followed.
	if err := audit.Record(ctx, tx, by.EventIn(c.OrganizationID, metAction(c.RiskEmail), "user", c.UserID,
		map[string]any{"first_factor": c.FirstFactor, "proof": metProofKind(proof, c.Enrollment, c.RiskEmail)})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// deferEnrollment consumes an enrolment challenge skipped while the grace
// period runs, and audits it. Refused (ErrMFAEnrollmentRequired) once the
// account must set up a factor now; refusing costs no attempt.
func (s *Service) deferEnrollment(ctx context.Context, tx pgx.Tx, id uuid.UUID, met metChallenge) (metChallenge, error) {
	graceUntil, err := s.mayDeferEnrollment(ctx, tx, met.userID, met.organizationID)
	if err != nil {
		return metChallenge{}, err
	}
	if err := s.q.WithTx(tx).DeleteMFALoginChallenge(ctx, id); err != nil {
		return metChallenge{}, err
	}
	meta := map[string]any{"first_factor": met.firstFactor}
	if graceUntil != nil {
		meta["grace_until"] = graceUntil
	}
	if err := audit.Record(ctx, tx, audit.Actor{UserID: &met.userID, Type: "user"}.EventIn(orNil(met.organizationID),
		"auth.mfa_enrollment_deferred", "user", met.userID, meta)); err != nil {
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
	// maxMFAFailureStreak is how many wrong second factors in a row lock a
	// person's second-factor sign-in, whatever the windows above allow.
	maxMFAFailureStreak = 50
)

// lockMFASignIn locks userID's second-factor sign-in inside tx, at the end of
// a run of failures wrong answers, and audits it.
func (s *Service) lockMFASignIn(ctx context.Context, tx pgx.Tx, userID uuid.UUID, organizationID *uuid.UUID, failures int) error {
	if err := dbgen.New(tx).LockMFASignIn(ctx, userID); err != nil {
		return err
	}
	return audit.Record(ctx, tx, audit.Actor{UserID: &userID, Type: "user"}.EventIn(organizationID, "auth.mfa_locked", "user", userID,
		map[string]any{"failures": failures}))
}

// noticeMFALocked tells the person their second-factor sign-in locked, as
// whoever entered the codes knew their password. Best effort: the lock stands.
func (s *Service) noticeMFALocked(ctx context.Context, userID uuid.UUID) {
	email, err := s.q.AccountEmail(ctx, userID)
	if err != nil {
		slog.Warn("auth: could not read the address for an MFA lock notice", "user_id", userID, "err", err)
		return
	}
	intro := "Many wrong verification codes were entered after your password while signing in to your Qeet ID account, so signing in with a second factor is now locked."
	note := "Whoever entered them knew your password. Reset your password from the sign-in page to unlock your account."
	if err := s.sender.Send(ctx, notifier.Message{
		Channel: "email",
		To:      email,
		Subject: "Your sign-in was locked",
		Body:    intro + " " + note,
		HTML:    emailtmpl.Notice("Your sign-in was locked", intro, note),
	}); err != nil {
		slog.Warn("auth: could not send an MFA lock notice", "user_id", userID, "err", err)
	}
}

func reserveLoginMFAAttempt(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (int, error) {
	q := dbgen.New(tx)
	if err := q.EnsureLoginAttemptBudget(ctx, userID); err != nil {
		return 0, err
	}
	budget, err := q.LockLoginAttemptBudget(ctx, userID)
	if err != nil {
		return 0, err
	}
	failed, windowStarted, lockedUntil := budget.FailedAttempts, budget.WindowStartedAt, budget.LockedUntil
	now := time.Now().UTC()
	if lockedUntil != nil && now.Before(*lockedUntil) {
		return 0, errs.ErrMFAAttemptsExceeded.WithMetadata(map[string]any{"remaining_attempts": 0})
	}
	if now.Sub(windowStarted) >= mfaLoginAttemptWindow || (lockedUntil != nil && !now.Before(*lockedUntil)) {
		failed = 0
		windowStarted = now
	}
	next := failed + 1
	var lock *time.Time
	if next >= maxMFALoginAttempts {
		lock = new(now.Add(mfaLoginAttemptWindow))
	}
	if err := q.SetLoginAttemptBudget(ctx, dbgen.SetLoginAttemptBudgetParams{
		UserID: userID, FailedAttempts: next, WindowStartedAt: windowStarted, LockedUntil: lock,
	}); err != nil {
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
	if err := s.refuseSignIn(ctx, met.userID, met.organizationID, met.method(), ip, ua); err != nil {
		return nil, nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, met.userID, met.organizationID, ip, ua, met.method(), met.claims, nil, time.Time{})
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
	countSignIn(met.method())
	s.recordSignIn(ctx, met.userID, met.organizationID, ua, httpx.GeoCountry(ctx))
	return pair, met.recoveryCodes, nil
}

// MFALoginSession is a hosted-login challenge met: the SSO session cookie
// value to write via SetLoginSessionCookie, and the recovery codes minted
// when the challenge was met by setting up an authenticator app.
type MFALoginSession struct {
	UserID uuid.UUID
	// OrganizationID is uuid.Nil when organization-less.
	OrganizationID uuid.UUID
	RawCookie      string
	RecoveryCodes  []string
	// Deferred: an enrolment challenge skipped in the grace period. No
	// factor was met, so the device must not be remembered.
	Deferred bool
}

// CompleteMFALoginSession verifies the second-factor code for a pending
// hosted-login challenge and returns the user ID, the organization ID (uuid.Nil if
// none) and the SSO session cookie value.
func (s *Service) CompleteMFALoginSession(ctx context.Context, mfaToken, code, ip, ua string) (uuid.UUID, uuid.UUID, string, error) {
	res, err := s.CompleteMFALoginSessionWith(ctx, mfaToken, MFAProof{Code: code}, ip, ua)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", err
	}
	return res.UserID, res.OrganizationID, res.RawCookie, nil
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
	raw, err := s.createLoginSession(ctx, met.userID, met.organizationID, ip, ua, met.method(), factor)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, met.userID, met.organizationID, ua, httpx.GeoCountry(ctx))
	// A confirmed risky sign-in met no factor either, so earns no remembered device.
	return &MFALoginSession{UserID: met.userID, OrganizationID: met.organizationID, RawCookie: raw,
		RecoveryCodes: met.recoveryCodes, Deferred: met.deferred || met.riskVerified}, nil
}
