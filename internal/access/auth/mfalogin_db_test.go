//go:build integration

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestSignInCodeSending checks that a code for a challenged sign-in is sent
// with only one connection free, and that one that fails to go is not
// counted against the challenge.
func TestSignInCodeSending(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	factor := uuid.New()
	mfa := &poolFactors{pool: pool, factors: []LoginFactor{{Type: "email", ID: &factor}}}
	svc.mfa = mfa
	a, _ := member(t)
	res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.MFARequired || res.EnrollmentRequired {
		t.Fatalf("sign in: %+v, %v; want a challenge", res, err)
	}
	sent := func() int {
		return dbtest.Count(t, `SELECT codes_sent FROM auth.mfa_login_challenges WHERE id = $1`, res.MFAToken)
	}

	dbtest.LeaveOneConnection(t)
	if err := svc.SendMFACode(ctx, res.MFAToken, factor); err != nil {
		t.Fatalf("send a code: %v", err)
	}
	mfa.failSend = true
	if err := svc.SendMFACode(ctx, res.MFAToken, factor); !errors.Is(err, errs.ErrMFADeliveryFailed) {
		t.Fatalf("send a code that fails to go: %v, want %v", err, errs.ErrMFADeliveryFailed)
	}
	if n := sent(); n != 1 {
		t.Errorf("%d codes counted, want 1: the one that failed to go was counted", n)
	}
}

// TestPasskeyAndPushChallengeWithOneConnection checks that a passkey ceremony
// and a push request are begun for a challenge, and bound to it, with only one
// connection free.
func TestPasskeyAndPushChallengeWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.mfa = &poolFactors{pool: pool, factors: []LoginFactor{{Type: "passkey"}, {Type: "push"}}}
	a, _ := member(t)
	res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.MFARequired || res.EnrollmentRequired {
		t.Fatalf("sign in: %+v, %v; want a challenge", res, err)
	}

	dbtest.LeaveOneConnection(t)
	sessionID, _, err := svc.BeginMFAPasskey(ctx, res.MFAToken)
	if err != nil {
		t.Fatalf("begin the passkey ceremony: %v", err)
	}
	if _, _, err := svc.StartMFAPush(ctx, res.MFAToken, "", ""); err != nil {
		t.Fatalf("start the push request: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges WHERE id = $1
		AND passkey_session_id = $2 AND push_challenge_id IS NOT NULL`, res.MFAToken, sessionID); n != 1 {
		t.Error("the ceremony and the push request are not bound to the challenge")
	}
}

// TestFailedSendUndoneAfterTheContextEnds checks that a code whose send fails
// because the request's context ended is still not counted, and a risk
// challenge's earlier code still stands.
func TestFailedSendUndoneAfterTheContextEnds(t *testing.T) {
	pool := dbtest.Pool(t)
	a, _ := member(t)
	if _, err := pool.Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	challenge := func(t *testing.T, svc *Service) string {
		t.Helper()
		res, err := svc.Login(dbtest.Context(t), LoginInput{Email: a.Email, Password: testPassword})
		if err != nil || res.MFAToken == "" {
			t.Fatalf("sign in: %+v, %v; want a challenge", res, err)
		}
		return res.MFAToken
	}
	codesSent := func(token string) int {
		return dbtest.Count(t, `SELECT codes_sent FROM auth.mfa_login_challenges WHERE id = $1`, token)
	}

	t.Run("sign-in code", func(t *testing.T) {
		svc := newService(t)
		factor := uuid.New()
		mfa := &poolFactors{pool: pool, factors: []LoginFactor{{Type: "email", ID: &factor}}}
		svc.mfa = mfa
		token := challenge(t, svc)
		ctx, cancel := context.WithCancel(dbtest.Context(t))
		mfa.cancelSend = cancel
		if err := svc.SendMFACode(ctx, token, factor); err == nil {
			t.Fatal("a send that ended the context succeeded")
		}
		if n := codesSent(token); n != 0 {
			t.Errorf("%d codes counted, want 0", n)
		}
	})
	t.Run("risk email code", func(t *testing.T) {
		svc := newService(t)
		svc.mfa = &poolFactors{pool: pool}
		svc.riskAssessor = &riskStub{risky: true}
		ctx, cancel := context.WithCancel(dbtest.Context(t))
		svc.sender = &cancellingMailbox{cancel: cancel}
		token := challenge(t, svc)
		if err := svc.SendMFACode(ctx, token, uuid.MustParse(token)); !errors.Is(err, errs.ErrMFADeliveryFailed) {
			t.Fatalf("send: %v, want %v", err, errs.ErrMFADeliveryFailed)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges
			WHERE id = $1 AND codes_sent = 0 AND email_code_hash IS NULL AND email_code_sent_at IS NULL`, token); n != 1 {
			t.Error("the challenge is not as it was before the failed send")
		}
	})
}
