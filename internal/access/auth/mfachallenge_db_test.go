//go:build integration

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// pinnedFactors is an MFA service for driving verifyAndConsumeMFAChallenge:
// accounts hold factors (none: they still need to set one up), the
// authenticator accepts code, an enrolment is confirmed by enrolCode, and a
// push request has status push.
type pinnedFactors struct {
	MFAEnroller
	factors   []LoginFactor
	code      string
	enrolCode string
	push      string
}

func (f pinnedFactors) LoginFactorsTx(context.Context, pgx.Tx, uuid.UUID) ([]LoginFactor, error) {
	return f.factors, nil
}

func (f pinnedFactors) VerifyForLoginTx(_ context.Context, _ pgx.Tx, _ uuid.UUID, code string) (string, error) {
	if code != f.code {
		return "", nil
	}
	return "totp", nil
}

func (f pinnedFactors) ConfirmLoginEnrollment(_ context.Context, _ pgx.Tx, _ uuid.UUID, code string) ([]string, bool, error) {
	if code != f.enrolCode {
		return nil, false, nil
	}
	return []string{"recovery-1", "recovery-2"}, true, nil
}

func (f pinnedFactors) LoginPushStatusTx(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) (string, error) {
	return f.push, nil
}

// pendingChallenge is a sign-in challenge as stored, for a test to set up.
type pendingChallenge struct {
	enrollment, enrollmentStarted, riskEmail bool
	failedAttempts                           int16
	expiresAt                                time.Time
	pushChallenge                            *uuid.UUID
	emailCode                                string
}

// newChallenge stores c for a in organization and returns its token.
func newChallenge(t *testing.T, a dbtest.Account, organization uuid.UUID, c pendingChallenge) string {
	t.Helper()
	if c.expiresAt.IsZero() {
		c.expiresAt = time.Now().Add(mfaChallengeTTL)
	}
	var hash, expires any
	if c.emailCode != "" {
		hash, expires = codes.Hash(c.emailCode), time.Now().Add(time.Minute)
	}
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		INSERT INTO auth.mfa_login_challenges (user_id, organization_id, expires_at, claims, enrollment, enrollment_started,
		                                       risk_email, failed_attempts, push_challenge_id, email_code_hash, email_code_expires_at)
		VALUES ($1, $2, $3, '{"team":"blue"}', $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		a.ID, organization, c.expiresAt, c.enrollment, c.enrollmentStarted, c.riskEmail, c.failedAttempts, c.pushChallenge,
		hash, expires).Scan(&id); err != nil {
		t.Fatalf("store challenge: %v", err)
	}
	return id.String()
}

// challengeState is what a challenge left behind: whether it is still there
// and its failure count, the account's sign-in attempt budget, its run of
// wrong answers and the audit rows written for it.
type challengeState struct {
	exists          bool
	failed          int
	budget, streak  int
	locked          bool
	failedSignIns   int
	verified        int
	confirmed       int
	enrolled        int
	deferred        int
	mfaLocked       int
	lastFailureMeta map[string]any
}

func stateOf(t *testing.T, a dbtest.Account, token string) challengeState {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	var st challengeState
	err := pool.QueryRow(ctx, `SELECT failed_attempts FROM auth.mfa_login_challenges WHERE id::text = $1`, token).Scan(&st.failed)
	st.exists = err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT failed_attempts FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = 'login'`, a.ID).Scan(&st.budget)
	_ = pool.QueryRow(ctx, `SELECT failures, locked_at IS NOT NULL FROM auth.mfa_failure_streaks WHERE user_id = $1`, a.ID).Scan(&st.streak, &st.locked)
	count := func(action string) int {
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND resource_id = $2`, action, a.ID)
	}
	st.failedSignIns, st.verified, st.confirmed = count("auth.sign_in_failed"), count("auth.mfa_verified"), count("auth.sign_in_confirmed")
	st.enrolled, st.deferred, st.mfaLocked = count("mfa.totp_enrolled"), count("auth.mfa_enrollment_deferred"), count("auth.mfa_locked")
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT metadata FROM audit.events WHERE action = 'auth.sign_in_failed' AND resource_id = $1
		ORDER BY created_at DESC LIMIT 1`, a.ID).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &st.lastFailureMeta)
	}
	return st
}

// remaining is the remaining_attempts an error carries, or -1.
func remaining(err error) int {
	if e := errs.As(err); e != nil {
		if n, ok := e.Metadata["remaining_attempts"].(int); ok {
			return n
		}
	}
	return -1
}

// TestVerifyAndConsumeMFAChallenge pins what checking a sign-in's second step
// does for each kind of challenge and proof: the answer, what it consumes or
// counts (the challenge, the account's attempt budget, its run of wrong
// answers) and the audit rows it writes.
func TestVerifyAndConsumeMFAChallenge(t *testing.T) {
	ctx := dbtest.Context(t)
	held := pinnedFactors{factors: []LoginFactor{{Type: "totp"}}, code: "135790", push: "pending"}
	setup := func(t *testing.T, f pinnedFactors) (*Service, dbtest.Account, uuid.UUID) {
		t.Helper()
		svc := newService(t)
		svc.SetMFA(f)
		a, organization := member(t)
		return svc, a, organization
	}

	t.Run("unusable tokens", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, "not-a-token", MFAProof{Code: "135790"}, "", ""); !errors.Is(err, errs.ErrAuthSessionInvalid) {
			t.Errorf("malformed token: %v, want %v", err, errs.ErrAuthSessionInvalid)
		}
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, uuid.NewString(), MFAProof{Code: "135790"}, "", ""); !errors.Is(err, errs.ErrAuthMFAChallengeExpired) {
			t.Errorf("unknown token: %v, want %v", err, errs.ErrAuthMFAChallengeExpired)
		}
		token := newChallenge(t, a, organization, pendingChallenge{expiresAt: time.Now().Add(-time.Second)})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "135790"}, "", ""); !errors.Is(err, errs.ErrAuthMFAChallengeExpired) {
			t.Errorf("expired challenge: %v, want %v", err, errs.ErrAuthMFAChallengeExpired)
		}
		if st := stateOf(t, a, token); st.exists || st.budget != 0 || st.failedSignIns != 0 {
			t.Errorf("after an expired challenge: %+v; want it removed and nothing counted", st)
		}
		svc.SetMFA(nil)
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, uuid.NewString(), MFAProof{}, "", ""); !errors.Is(err, errs.ErrNotImplemented) {
			t.Errorf("without an MFA service: %v, want %v", err, errs.ErrNotImplemented)
		}
	})

	t.Run("refused before an attempt is counted", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		for _, tc := range []struct {
			name      string
			challenge pendingChallenge
			proof     MFAProof
			want      error
		}{
			{"skip a factor", pendingChallenge{}, MFAProof{Skip: true}, errs.ErrBadRequest},
			{"skip a risk confirmation", pendingChallenge{riskEmail: true}, MFAProof{Skip: true}, errs.ErrBadRequest},
			{"push for an enrolment", pendingChallenge{enrollment: true, enrollmentStarted: true}, MFAProof{Push: true}, errNotAFactorChallenge},
			{"enrolment not started", pendingChallenge{enrollment: true}, MFAProof{Code: "000000"}, errs.ErrMFAEnrollNotStarted},
			{"pending push", pendingChallenge{pushChallenge: new(uuid.New())}, MFAProof{Push: true}, errs.ErrMFAPushPending},
		} {
			token := newChallenge(t, a, organization, tc.challenge)
			if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, tc.proof, "", ""); !errors.Is(err, tc.want) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
			}
			if st := stateOf(t, a, token); !st.exists || st.failed != 0 || st.budget != 0 || st.streak != 0 || st.failedSignIns != 0 {
				t.Errorf("%s left %+v; want the challenge untouched and nothing counted", tc.name, st)
			}
		}
	})

	t.Run("wrong then right code", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		token := newChallenge(t, a, organization, pendingChallenge{})
		_, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "000000"}, "192.0.2.4", "test-agent")
		if !errors.Is(err, errs.ErrMFACodeInvalid) || remaining(err) != 4 {
			t.Fatalf("wrong code: %v (remaining %d), want %v with 4 left", err, remaining(err), errs.ErrMFACodeInvalid)
		}
		st := stateOf(t, a, token)
		if !st.exists || st.failed != 1 || st.budget != 1 || st.streak != 1 || st.failedSignIns != 1 ||
			st.lastFailureMeta["remaining_attempts"] != float64(4) || st.lastFailureMeta["first_factor"] != "password" ||
			st.lastFailureMeta["method"] != "mfa" || st.lastFailureMeta["reason"] != FailureCodeInvalid {
			t.Errorf("after a wrong code: %+v", st)
		}
		met, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "135790"}, "192.0.2.4", "test-agent")
		if err != nil || met.userID != a.ID || met.organizationID != organization || met.stepUpMethod != "totp" ||
			met.claims["team"] != "blue" || met.method() != "password_mfa" {
			t.Fatalf("right code: %+v, %v", met, err)
		}
		if st := stateOf(t, a, token); st.exists || st.budget != 0 || st.streak != 0 || st.verified != 1 {
			t.Errorf("after the right code: %+v; want the challenge, budget and run of wrong answers gone, and auth.mfa_verified", st)
		}
	})

	t.Run("last attempt on the challenge", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		token := newChallenge(t, a, organization, pendingChallenge{failedAttempts: maxMFALoginAttempts - 1})
		_, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "000000"}, "", "")
		if !errors.Is(err, errs.ErrMFAAttemptsExceeded) || remaining(err) != 0 {
			t.Fatalf("fifth wrong code: %v, want %v with none left", err, errs.ErrMFAAttemptsExceeded)
		}
		if st := stateOf(t, a, token); st.exists || st.failedSignIns != 1 || st.lastFailureMeta["remaining_attempts"] != float64(0) {
			t.Errorf("after the last attempt: %+v; want the challenge removed and the failure recorded", st)
		}
	})

	t.Run("long run of wrong answers locks", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.mfa_failure_streaks (user_id, failures) VALUES ($1, $2)`,
			a.ID, maxMFAFailureStreak-1); err != nil {
			t.Fatal(err)
		}
		token := newChallenge(t, a, organization, pendingChallenge{})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "000000"}, "", ""); !errors.Is(err, errs.ErrMFALocked) {
			t.Fatalf("wrong code ending the run: %v, want %v", err, errs.ErrMFALocked)
		}
		st := stateOf(t, a, token)
		if st.exists || !st.locked || st.mfaLocked != 1 || st.failedSignIns != 1 {
			t.Errorf("after the lock: %+v; want the challenge removed, the lock set and audited, and the failure recorded", st)
		}
		token = newChallenge(t, a, organization, pendingChallenge{})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "135790"}, "", ""); !errors.Is(err, errs.ErrMFALocked) {
			t.Errorf("right code while locked: %v, want %v", err, errs.ErrMFALocked)
		}
	})

	t.Run("risk email confirmation", func(t *testing.T) {
		svc, a, organization := setup(t, held)
		token := newChallenge(t, a, organization, pendingChallenge{riskEmail: true, emailCode: "424242"})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "000000"}, "", ""); !errors.Is(err, errs.ErrMFACodeInvalid) {
			t.Fatalf("wrong emailed code: %v, want %v", err, errs.ErrMFACodeInvalid)
		}
		if st := stateOf(t, a, token); st.lastFailureMeta["proof"] != "email_confirmation" {
			t.Errorf("the failure was recorded as proof %v, want email_confirmation", st.lastFailureMeta["proof"])
		}
		met, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: " 424242 "}, "", "")
		if err != nil || !met.riskVerified || met.stepUpMethod != "" || met.method() != "password_email_confirmed" {
			t.Fatalf("right emailed code: %+v, %v", met, err)
		}
		if st := stateOf(t, a, token); st.exists || st.confirmed != 1 || st.verified != 0 {
			t.Errorf("after confirming: %+v; want auth.sign_in_confirmed and no auth.mfa_verified", st)
		}
	})

	t.Run("enrolment", func(t *testing.T) {
		svc, a, organization := setup(t, pinnedFactors{enrolCode: "112233"})
		token := newChallenge(t, a, organization, pendingChallenge{enrollment: true, enrollmentStarted: true})
		met, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "112233"}, "", "")
		if err != nil || met.stepUpMethod != "totp" || len(met.recoveryCodes) != 2 {
			t.Fatalf("confirming the app: %+v, %v", met, err)
		}
		if st := stateOf(t, a, token); st.exists || st.enrolled != 1 || st.verified != 1 {
			t.Errorf("after enrolling: %+v; want mfa.totp_enrolled and auth.mfa_verified", st)
		}
		token = newChallenge(t, a, organization, pendingChallenge{enrollment: true})
		met, err = svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Skip: true}, "", "")
		if err != nil || !met.deferred || met.method() != "password" {
			t.Fatalf("skipping with no requirement: %+v, %v", met, err)
		}
		if st := stateOf(t, a, token); st.exists || st.deferred != 1 || st.budget != 0 {
			t.Errorf("after deferring: %+v; want auth.mfa_enrollment_deferred and nothing counted", st)
		}
		svc.SetMFA(pinnedFactors{factors: []LoginFactor{{Type: "totp"}}, enrolCode: "112233"})
		token = newChallenge(t, a, organization, pendingChallenge{enrollment: true, enrollmentStarted: true})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Code: "112233"}, "", ""); !errors.Is(err, errs.ErrAuthMFAChallengeExpired) {
			t.Errorf("enrolling after gaining a factor: %v, want %v", err, errs.ErrAuthMFAChallengeExpired)
		}
	})

	t.Run("push", func(t *testing.T) {
		push := uuid.New()
		svc, a, organization := setup(t, pinnedFactors{push: "approved"})
		token := newChallenge(t, a, organization, pendingChallenge{pushChallenge: &push})
		met, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Push: true}, "", "")
		if err != nil || met.stepUpMethod != "push" {
			t.Fatalf("approved push: %+v, %v", met, err)
		}
		svc.SetMFA(pinnedFactors{push: "denied"})
		token = newChallenge(t, a, organization, pendingChallenge{pushChallenge: &push})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Push: true}, "", ""); !errors.Is(err, errs.ErrMFACodeInvalid) {
			t.Errorf("denied push: %v, want %v", err, errs.ErrMFACodeInvalid)
		}
		token = newChallenge(t, a, organization, pendingChallenge{})
		if _, err := svc.verifyAndConsumeMFAChallenge(ctx, token, MFAProof{Push: true}, "", ""); !errors.Is(err, errs.ErrMFACodeInvalid) {
			t.Errorf("push for a challenge with no request: %v, want %v", err, errs.ErrMFACodeInvalid)
		}
	})
}
