//go:build integration

package authentication

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRiskEmailCodeSending checks that a risky sign-in's emailed code is sent
// with only one connection free, at most one per riskEmailResendAfter, that
// each replaces the last, and that one that fails to go leaves the challenge
// as it was.
func TestRiskEmailCodeSending(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.mfa = &poolFactors{pool: pool}
	svc.riskAssessor = &riskStub{risky: true}
	mail := &poolMailbox{pool: pool}
	svc.sender = mail
	a, _ := member(t)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || len(res.Methods) != 1 || res.Methods[0] != "email" {
		t.Fatalf("risky sign-in: %+v, %v; want an emailed-code challenge", res, err)
	}
	id := uuid.MustParse(res.MFAToken)
	type state struct {
		Hash   *string
		SentAt *time.Time
		Sent   int
	}
	read := func() (st state) {
		if err := pool.QueryRow(ctx, `SELECT email_code_hash, email_code_sent_at, codes_sent FROM auth.mfa_login_challenges WHERE id = $1`, id).
			Scan(&st.Hash, &st.SentAt, &st.Sent); err != nil {
			t.Fatalf("read the challenge: %v", err)
		}
		return st
	}
	// resendable moves the last code back past the resend wait.
	resendable := func() {
		if _, err := pool.Exec(ctx, `UPDATE auth.mfa_login_challenges SET email_code_sent_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}

	dbtest.LeaveOneConnection(t)
	if err := svc.SendMFACode(ctx, res.MFAToken, id); err != nil {
		t.Fatalf("send the code: %v", err)
	}
	first := mail.Last(t).Body
	if err := svc.SendMFACode(ctx, res.MFAToken, id); !errors.Is(err, errs.ErrMFACodeSendLimited) {
		t.Fatalf("send again at once: %v, want %v", err, errs.ErrMFACodeSendLimited)
	}
	resendable()
	if err := svc.SendMFACode(ctx, res.MFAToken, id); err != nil {
		t.Fatalf("send again after the wait: %v", err)
	}
	if mail.Len() != 2 || mail.Last(t).Body == first {
		t.Fatalf("%d codes sent; want a second, different one", mail.Len())
	}
	latest := mail.Last(t).Body

	resendable()
	before := read()
	mail.fail = true
	if err := svc.SendMFACode(ctx, res.MFAToken, id); !errors.Is(err, errs.ErrMFADeliveryFailed) {
		t.Fatalf("send a code that fails to go: %v, want %v", err, errs.ErrMFADeliveryFailed)
	}
	if after := read(); *after.Hash != *before.Hash || !after.SentAt.Equal(*before.SentAt) || after.Sent != before.Sent {
		t.Fatalf("challenge after a failed send %+v, want it as it was, %+v", after, before)
	}
	mail.fail = false

	code := latest[strings.Index(latest, "code: ")+len("code: "):][:6]
	pair, _, err := svc.CompleteMFALoginWith(ctx, res.MFAToken, MFAProof{Code: code}, "", "")
	if err != nil || pair == nil {
		t.Fatalf("confirm with the latest code: %+v, %v", pair, err)
	}
}

// TestRiskRecordsOnlyIssuedSignIns checks that a sign-in is recorded for risk
// once its session is issued, and not when it passes the risk assessment but
// is then refused at the session limit or for its address, whether it signs
// in at once or completes a challenge.
func TestRiskRecordsOnlyIssuedSignIns(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	login := func(svc *Service, a dbtest.Account) (*LoginResult, error) {
		return svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	}

	t.Run("signed in", func(t *testing.T) {
		svc, risk := newService(t), &riskStub{}
		svc.riskAssessor = risk
		a, _ := member(t)
		if res, err := login(svc, a); err != nil || res.Pair == nil {
			t.Fatalf("sign in: %+v, %v", res, err)
		}
		if risk.recorded != 1 {
			t.Errorf("recorded %d times, want 1", risk.recorded)
		}
	})
	t.Run("refused at the session limit", func(t *testing.T) {
		svc, risk := newService(t), &riskStub{}
		svc.riskAssessor = risk
		a, organization := member(t)
		atSessionLimit(t, svc, a, organization)
		if _, err := login(svc, a); !errors.Is(err, ErrSessionLimit) {
			t.Fatalf("sign in: %v, want %v", err, ErrSessionLimit)
		}
		if risk.recorded != 0 {
			t.Errorf("recorded %d times, want 0", risk.recorded)
		}
	})
	t.Run("refused for its address", func(t *testing.T) {
		svc, risk := newService(t), &riskStub{}
		svc.riskAssessor = risk
		svc.addresses = addressFunc(func(context.Context, uuid.UUID, uuid.UUID, string, string) error {
			return errs.ErrAuthAddressNotAllowed
		})
		a, _ := member(t)
		if _, err := login(svc, a); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			t.Fatalf("sign in: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
		}
		if risk.recorded != 0 {
			t.Errorf("recorded %d times, want 0", risk.recorded)
		}
	})
	t.Run("challenge met, then refused at the session limit", func(t *testing.T) {
		svc, risk, mail := newService(t), &riskStub{risky: true}, &dbtest.Mailbox{}
		svc.riskAssessor = risk
		svc.mfa = &poolFactors{pool: pool}
		svc.sender = mail
		a, organization := member(t)
		if _, err := pool.Exec(ctx, `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		atSessionLimit(t, svc, a, organization)
		res, err := login(svc, a)
		if err != nil || res.MFAToken == "" {
			t.Fatalf("risky sign-in: %+v, %v; want a challenge", res, err)
		}
		if err := svc.SendMFACode(ctx, res.MFAToken, uuid.MustParse(res.MFAToken)); err != nil {
			t.Fatalf("send the code: %v", err)
		}
		body := mail.Last(t).Body
		code := body[strings.Index(body, "code: ")+len("code: "):][:6]
		if _, _, err := svc.CompleteMFALoginWith(ctx, res.MFAToken, MFAProof{Code: code}, "", ""); !errors.Is(err, ErrSessionLimit) {
			t.Fatalf("confirm: %v, want %v", err, ErrSessionLimit)
		}
		if risk.recorded != 0 {
			t.Errorf("recorded %d times, want 0", risk.recorded)
		}
	})
}
