//go:build integration

package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// enforceAddressRules turns tenant's address rules on with one allow rule for
// 192.0.2.0/24, so every sign-in to it and renewal in it reads them.
func enforceAddressRules(t *testing.T, tenant uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		WITH rule AS (INSERT INTO tenant.ip_rules (tenant_id, cidr, label, action) VALUES ($1, '192.0.2.0/24', 'office', 'allow'))
		INSERT INTO tenant.ip_rules_config (tenant_id, enabled) VALUES ($1, TRUE)
	`, tenant); err != nil {
		t.Fatalf("address rules: %v", err)
	}
}

// concurrently runs fn n times at once and returns the errors.
func concurrently(n int, fn func(i int) error) []error {
	out := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { out[i] = fn(i) })
	}
	wg.Wait()
	return out
}

// TestConcurrentSignInsShareASmallPool checks that more sign-ins, and then
// renewals, than the pool has connections all complete when run at once: none
// holds its transaction while it waits for a second connection.
func TestConcurrentSignInsShareASmallPool(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetAddressPolicy(ipallow.NewService(pool))
	a, tenant := member(t)
	enforceAddressRules(t, tenant)
	n := 3 * int(pool.Config().MaxConns)

	pairs := make([]*TokenPair, n)
	for i, err := range concurrently(n, func(i int) (err error) {
		pairs[i], err = svc.IssuePair(ctx, a.ID, tenant, "192.0.2.10", "test", "password")
		return err
	}) {
		if err != nil {
			t.Fatalf("sign-in %d: %v", i, err)
		}
	}
	for i, err := range concurrently(n, func(i int) error {
		_, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pairs[i].RefreshToken, IP: "192.0.2.10"})
		return err
	}) {
		if err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
	}
}

// TestRenewalFromARefusedAddress checks that a renewal from an address the
// organisation's rules refuse is refused and recorded, and that the refresh
// token still renews from an allowed address.
func TestRenewalFromARefusedAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetAddressPolicy(ipallow.NewService(pool))
	a, tenant := member(t)
	enforceAddressRules(t, tenant)
	pair, err := svc.IssuePair(ctx, a.ID, tenant, "192.0.2.10", "test", "password")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}

	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken, IP: "198.51.100.7"}); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Fatalf("renewal from a refused address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.address_refused' AND tenant_id = $1
		AND metadata->>'path' = 'refresh' AND metadata->>'address' = '198.51.100.7'`, tenant); n != 1 {
		t.Errorf("the refused renewal was recorded %d times, want 1", n)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken, IP: "192.0.2.10"}); err != nil {
		t.Errorf("renewal from an allowed address after a refused one: %v", err)
	}
}

// poolFactors is an MFA service whose accounts hold factors. Like the MFA
// service, its methods that take a transaction work through it and the rest
// through the pool; SendLoginCode then fails while failSend is set.
type poolFactors struct {
	MFAEnroller
	pool     *pgxpool.Pool
	factors  []LoginFactor
	failSend bool
	// cancelSend, when set, makes SendLoginCode fail by ending the context.
	cancelSend context.CancelFunc
}

func (f *poolFactors) LoginFactors(ctx context.Context, _ uuid.UUID) ([]LoginFactor, error) {
	return f.factors, f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) LoginFactorsTx(ctx context.Context, tx pgx.Tx, _ uuid.UUID) ([]LoginFactor, error) {
	return f.factors, tx.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) StartLoginEnrollment(ctx context.Context, tx pgx.Tx, _ uuid.UUID, _ string) (string, string, error) {
	return "secret", "otpauth://totp/test", tx.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) BeginLoginPasskey(ctx context.Context, _ uuid.UUID) (uuid.UUID, any, error) {
	return uuid.New(), "options", f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) StartLoginPush(ctx context.Context, _ uuid.UUID, _, _ string) (uuid.UUID, time.Time, error) {
	return uuid.New(), time.Now().Add(time.Minute), f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
}

func (f *poolFactors) SendLoginCode(ctx context.Context, _ uuid.UUID, _ *uuid.UUID, _ uuid.UUID) error {
	if err := f.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return err
	}
	if f.cancelSend != nil {
		f.cancelSend()
		return ctx.Err()
	}
	if f.failSend {
		return errs.ErrMFADeliveryFailed
	}
	return nil
}

// poolMailbox is a sender that reads through the pool before it sends, as the
// delivery tracker does, and refuses every message while fail is set.
type poolMailbox struct {
	dbtest.Mailbox
	pool *pgxpool.Pool
	fail bool
}

func (m *poolMailbox) Send(ctx context.Context, msg notifier.Message) error {
	if err := m.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return err
	}
	if m.fail {
		return errors.New("provider unavailable")
	}
	return m.Mailbox.Send(ctx, msg)
}

// TestEnrollmentChallengeWithOneConnection checks that an enrolment challenge
// can be started, and skipped in the grace period to sign in, with only one
// connection free.
func TestEnrollmentChallengeWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetMFA(&poolFactors{pool: pool})
	a, tenant := member(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 7, NOW())
	`, tenant); err != nil {
		t.Fatalf("require MFA: %v", err)
	}
	res, err := svc.Login(ctx, LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.EnrollmentRequired || res.EnrollmentDueAt == nil {
		t.Fatalf("sign in: %+v, %v; want an enrolment challenge that may be skipped", res, err)
	}

	dbtest.LeaveOneConnection(t)
	if _, err := svc.StartMFAEnrollment(ctx, res.MFAToken, "", ""); err != nil {
		t.Fatalf("start enrolment: %v", err)
	}
	pair, _, err := svc.CompleteMFALoginWith(ctx, res.MFAToken, MFAProof{Skip: true}, "", "")
	if err != nil || pair == nil {
		t.Fatalf("skip enrolment: %+v, %v", pair, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.mfa_enrollment_deferred' AND actor_user_id = $1`, a.ID); n != 1 {
		t.Errorf("the skipped enrolment was audited %d times, want 1", n)
	}
}

// TestSignInCodeSending checks that a code for a challenged sign-in is sent
// with only one connection free, and that one that fails to go is not
// counted against the challenge.
func TestSignInCodeSending(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	factor := uuid.New()
	mfa := &poolFactors{pool: pool, factors: []LoginFactor{{Type: "email", ID: &factor}}}
	svc.SetMFA(mfa)
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

// TestRiskEmailCodeSending checks that a risky sign-in's emailed code is sent
// with only one connection free, at most one per riskEmailResendAfter, that
// each replaces the last, and that one that fails to go leaves the challenge
// as it was.
func TestRiskEmailCodeSending(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetMFA(&poolFactors{pool: pool})
	svc.SetRiskAssessor(&riskStub{risky: true})
	mail := &poolMailbox{pool: pool}
	svc.SetSender(mail)
	a, _ := member(t)
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
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

// TestPasskeyAndPushChallengeWithOneConnection checks that a passkey ceremony
// and a push request are begun for a challenge, and bound to it, with only one
// connection free.
func TestPasskeyAndPushChallengeWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	svc.SetMFA(&poolFactors{pool: pool, factors: []LoginFactor{{Type: "passkey"}, {Type: "push"}}})
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
	if _, err := svc.StartMFAPush(ctx, res.MFAToken, "", ""); err != nil {
		t.Fatalf("start the push request: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges WHERE id = $1
		AND passkey_session_id = $2 AND push_challenge_id IS NOT NULL`, res.MFAToken, sessionID); n != 1 {
		t.Error("the ceremony and the push request are not bound to the challenge")
	}
}

// atSessionLimit caps a's sessions in tenant at one, refusing a sign-in beyond
// it, and opens that one session.
func atSessionLimit(t *testing.T, svc *Service, a dbtest.Account, tenant uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO tenant.security_policies (tenant_id, max_sessions, session_limit_action) VALUES ($1, 1, 'refuse')
	`, tenant); err != nil {
		t.Fatalf("session limit: %v", err)
	}
	if _, err := svc.IssuePair(dbtest.Context(t), a.ID, tenant, "", "test", "password"); err != nil {
		t.Fatalf("first session: %v", err)
	}
}

// sessionLimitRefusals counts the recorded refusals of a's sign-ins at the
// session limit.
func sessionLimitRefusals(t *testing.T, a dbtest.Account) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_refused_session_limit' AND resource_id = $1`, a.ID)
}

// TestSessionLimitRefusalWithOneConnection checks that a sign-in refused at
// the organisation's session limit is refused, and recorded, with only one
// connection free.
func TestSessionLimitRefusalWithOneConnection(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, tenant := member(t)
	atSessionLimit(t, svc, a, tenant)

	dbtest.LeaveOneConnection(t)
	if _, err := svc.IssuePair(ctx, a.ID, tenant, "", "test", "password"); !errors.Is(err, errs.ErrAuthSessionLimit) {
		t.Fatalf("sign in beyond the limit: %v, want %v", err, errs.ErrAuthSessionLimit)
	}
	if n := sessionLimitRefusals(t, a); n != 1 {
		t.Errorf("the refusal was recorded %d times, want 1", n)
	}
}

// TestConcurrentSessionLimitRefusals checks that more sign-ins beyond the
// session limit than the pool has connections, run at once, are all refused
// and recorded.
func TestConcurrentSessionLimitRefusals(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, tenant := member(t)
	atSessionLimit(t, svc, a, tenant)
	n := 3 * int(dbtest.Pool(t).Config().MaxConns)

	for i, err := range concurrently(n, func(int) error {
		_, err := svc.IssuePair(ctx, a.ID, tenant, "", "test", "password")
		return err
	}) {
		if !errors.Is(err, errs.ErrAuthSessionLimit) {
			t.Errorf("sign-in %d beyond the limit: %v, want %v", i, err, errs.ErrAuthSessionLimit)
		}
	}
	if got := sessionLimitRefusals(t, a); got != n {
		t.Errorf("%d refusals recorded, want %d", got, n)
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
		svc.SetRiskAssessor(risk)
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
		svc.SetRiskAssessor(risk)
		a, tenant := member(t)
		atSessionLimit(t, svc, a, tenant)
		if _, err := login(svc, a); !errors.Is(err, errs.ErrAuthSessionLimit) {
			t.Fatalf("sign in: %v, want %v", err, errs.ErrAuthSessionLimit)
		}
		if risk.recorded != 0 {
			t.Errorf("recorded %d times, want 0", risk.recorded)
		}
	})
	t.Run("refused for its address", func(t *testing.T) {
		svc, risk := newService(t), &riskStub{}
		svc.SetRiskAssessor(risk)
		svc.SetAddressPolicy(addressFunc(func(context.Context, uuid.UUID, uuid.UUID, string, string) error {
			return errs.ErrAuthAddressNotAllowed
		}))
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
		svc.SetRiskAssessor(risk)
		svc.SetMFA(&poolFactors{pool: pool})
		svc.SetSender(mail)
		a, tenant := member(t)
		if _, err := pool.Exec(ctx, `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
			t.Fatal(err)
		}
		atSessionLimit(t, svc, a, tenant)
		res, err := login(svc, a)
		if err != nil || res.MFAToken == "" {
			t.Fatalf("risky sign-in: %+v, %v; want a challenge", res, err)
		}
		if err := svc.SendMFACode(ctx, res.MFAToken, uuid.MustParse(res.MFAToken)); err != nil {
			t.Fatalf("send the code: %v", err)
		}
		body := mail.Last(t).Body
		code := body[strings.Index(body, "code: ")+len("code: "):][:6]
		if _, _, err := svc.CompleteMFALoginWith(ctx, res.MFAToken, MFAProof{Code: code}, "", ""); !errors.Is(err, errs.ErrAuthSessionLimit) {
			t.Fatalf("confirm: %v, want %v", err, errs.ErrAuthSessionLimit)
		}
		if risk.recorded != 0 {
			t.Errorf("recorded %d times, want 0", risk.recorded)
		}
	})
}

// cancellingMailbox is a sender whose send fails because it ends the
// request's context.
type cancellingMailbox struct{ cancel context.CancelFunc }

func (m *cancellingMailbox) Send(ctx context.Context, _ notifier.Message) error {
	m.cancel()
	return ctx.Err()
}

// TestFailedSendUndoneAfterTheContextEnds checks that a code whose send fails
// because the request's context ended is still not counted, and a risk
// challenge's earlier code still stands.
func TestFailedSendUndoneAfterTheContextEnds(t *testing.T) {
	pool := dbtest.Pool(t)
	a, _ := member(t)
	if _, err := pool.Exec(dbtest.Context(t), `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
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
		svc.SetMFA(mfa)
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
		svc.SetMFA(&poolFactors{pool: pool})
		svc.SetRiskAssessor(&riskStub{risky: true})
		ctx, cancel := context.WithCancel(dbtest.Context(t))
		svc.SetSender(&cancellingMailbox{cancel: cancel})
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
