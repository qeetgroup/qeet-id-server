//go:build integration

package mfa

import (
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

const testPassword = "Kx7mQ2vLp9Wz"

// sixDigits finds a sent one-time code.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// services returns the MFA service, sending codes through sender, and an
// authentication service that asks for its factors.
func services(t *testing.T, sender notifier.Sender) (*Service, *auth.Service) {
	t.Helper()
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	mfaSvc := NewService(pool, "Qeet", sender, "")
	mfaSvc.SetCipher(box)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(mfaSvc)
	return mfaSvc, authSvc
}

// member creates a member of a new organisation who signs in with
// testPassword.
func member(t *testing.T) (dbtest.Account, uuid.UUID) {
	t.Helper()
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, testPassword)
	return a, tenant
}

// inTx runs fn in a transaction, committed when fn succeeds.
func inTx(t *testing.T, fn func(tx pgx.Tx) error) error {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// enrolTOTP sets up an authenticator app for a and returns its secret and
// recovery codes.
func enrolTOTP(t *testing.T, svc *Service, a dbtest.Account) (string, []string) {
	t.Helper()
	ctx := dbtest.Context(t)
	var enrollment *Enrollment
	if err := inTx(t, func(tx pgx.Tx) (err error) {
		enrollment, err = svc.StartEnroll(ctx, tx, a.ID, a.Email)
		return err
	}); err != nil {
		t.Fatalf("start enrolment: %v", err)
	}
	attempt, err := svc.ReserveAttempt(ctx, a.ID, PurposeTOTPEnroll)
	if err != nil {
		t.Fatalf("reserve attempt: %v", err)
	}
	var recovery []string
	if err := inTx(t, func(tx pgx.Tx) (err error) {
		recovery, err = svc.ConfirmEnroll(ctx, tx, attempt, codeAt(t, enrollment.Secret, 0))
		return err
	}); err != nil {
		t.Fatalf("confirm enrolment: %v", err)
	}
	return enrollment.Secret, recovery
}

// challenge signs a in with testPassword and returns the second step's token.
func challenge(t *testing.T, authSvc *auth.Service, a dbtest.Account) string {
	t.Helper()
	res, err := authSvc.Login(dbtest.Context(t), auth.LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.MFARequired || res.MFAToken == "" {
		t.Fatalf("sign in: %+v, %v; want a second-factor challenge", res, err)
	}
	return res.MFAToken
}

// TestRecoveryCodesWorkOnce checks that a recovery code completes a sign-in
// once, and that regenerating the codes retires the old set.
func TestRecoveryCodesWorkOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, _ := member(t)
	_, recovery := enrolTOTP(t, mfaSvc, a)
	remaining := func() int {
		t.Helper()
		st, err := mfaSvc.RecoveryStatus(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return st.Remaining
	}
	if len(recovery) != recoveryCodeCount || remaining() != recoveryCodeCount {
		t.Fatalf("enrolment gave %d recovery codes, %d unused; want %d", len(recovery), remaining(), recoveryCodeCount)
	}

	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), recovery[0], "", ""); err != nil {
		t.Fatalf("sign in with a recovery code: %v", err)
	}
	if remaining() != recoveryCodeCount-1 {
		t.Errorf("%d recovery codes unused after one was used; want %d", remaining(), recoveryCodeCount-1)
	}
	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), recovery[0], "", ""); err == nil {
		t.Error("a used recovery code signed in again")
	}

	var fresh []string
	if err := inTx(t, func(tx pgx.Tx) (err error) {
		fresh, err = mfaSvc.Regenerate(ctx, tx, a.ID)
		return err
	}); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), recovery[1], "", ""); err == nil {
		t.Error("a recovery code from the replaced set signed in")
	}
	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), fresh[0], "", ""); err != nil {
		t.Errorf("sign in with a regenerated code: %v", err)
	}
}

// TestDisablingTheApp checks that once the authenticator app is removed, with
// its recovery codes, a password sign-in no longer asks for it.
func TestDisablingTheApp(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, _ := member(t)
	enrolTOTP(t, mfaSvc, a)
	if err := inTx(t, func(tx pgx.Tx) error { return mfaSvc.Disable(ctx, tx, a.ID) }); err != nil {
		t.Fatalf("disable: %v", err)
	}
	res, err := authSvc.Login(ctx, auth.LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || res.MFARequired || res.Pair == nil {
		t.Fatalf("sign in: %+v, %v; want tokens without a challenge", res, err)
	}
	if st, err := mfaSvc.RecoveryStatus(ctx, a.ID); err != nil || st.Enrolled || st.Total != 0 {
		t.Errorf("recovery codes after disabling: %+v, %v; want none", st, err)
	}
}

// TestEmailCodes checks that an email factor is confirmed only by the code
// sent to it, shown masked, completes a sign-in with a code sent then, and
// can be removed.
func TestEmailCodes(t *testing.T) {
	ctx := dbtest.Context(t)
	mail := &dbtest.Mailbox{}
	mfaSvc, authSvc := services(t, mail)
	a, tenant := member(t)

	factor, err := mfaSvc.EnrollOTPStart(ctx, a.ID, &tenant, "email", a.Email)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sent := mail.Last(t)
	code := sixDigits.FindString(sent.Body)
	if sent.To != a.Email || code == "" {
		t.Fatalf("sent %q to %s; want a code to %s", sent.Body, sent.To, a.Email)
	}
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	confirm := func(c string) error {
		t.Helper()
		attempt, err := mfaSvc.ReserveAttempt(ctx, a.ID, PurposeOTPEnroll(factor))
		if err != nil {
			t.Fatal(err)
		}
		return inTx(t, func(tx pgx.Tx) error { return mfaSvc.EnrollOTPConfirm(ctx, tx, attempt, factor, c) })
	}
	if err := confirm(wrong); !errors.Is(err, errs.ErrMFAOTPCodeInvalid) {
		t.Errorf("confirm with a wrong code: %v; want %v", err, errs.ErrMFAOTPCodeInvalid)
	}
	if err := confirm(code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	factors, err := mfaSvc.ListOTPFactors(ctx, a.ID)
	if err != nil || len(factors) != 1 || !factors[0].Verified || factors[0].Destination == a.Email {
		t.Fatalf("factors %+v, %v; want one confirmed, its address masked", factors, err)
	}

	// The resend wait is per factor: let it pass.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_otp_codes SET created_at = created_at - interval '1 minute' WHERE factor_id = $1`, factor); err != nil {
		t.Fatal(err)
	}
	token := challenge(t, authSvc, a)
	if err := authSvc.SendMFACode(ctx, token, factor); err != nil {
		t.Fatalf("send sign-in code: %v", err)
	}
	signInCode := sixDigits.FindString(mail.Last(t).Body)
	if pair, err := authSvc.CompleteMFALogin(ctx, token, signInCode, "", ""); err != nil || pair.UserID != a.ID {
		t.Fatalf("sign in with the emailed code: %+v, %v", pair, err)
	}

	if err := inTx(t, func(tx pgx.Tx) error { return mfaSvc.DeleteOTPFactor(ctx, tx, a.ID, factor) }); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if factors, err := mfaSvc.ListOTPFactors(ctx, a.ID); err != nil || len(factors) != 0 {
		t.Errorf("factors after removal: %+v, %v; want none", factors, err)
	}
}

// TestAttemptsAreLimited checks that a person gets five tries per purpose,
// that the limit of one purpose leaves another alone, and that a success
// gives the tries back.
func TestAttemptsAreLimited(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, _ := services(t, notifier.LogSender{})
	a, _ := member(t)
	for i := range maxMFAAttempts {
		if _, err := mfaSvc.ReserveAttempt(ctx, a.ID, PurposeFactorVerify); err != nil {
			t.Fatalf("try %d: %v", i+1, err)
		}
	}
	if _, err := mfaSvc.ReserveAttempt(ctx, a.ID, PurposeFactorVerify); !errors.Is(err, errs.ErrMFAAttemptsExceeded) {
		t.Errorf("a sixth try: %v; want %v", err, errs.ErrMFAAttemptsExceeded)
	}
	if _, err := mfaSvc.ReserveAttempt(ctx, a.ID, PurposeOTPVerify); err != nil {
		t.Errorf("another purpose after the limit: %v; want allowed", err)
	}

	b, _ := member(t)
	secret, _ := enrolTOTP(t, mfaSvc, b)
	var last Attempt
	for range maxMFAAttempts {
		var err error
		if last, err = mfaSvc.ReserveAttempt(ctx, b.ID, PurposeFactorVerify); err != nil {
			t.Fatal(err)
		}
	}
	if err := inTx(t, func(tx pgx.Tx) error {
		_, err := mfaSvc.Verify(ctx, tx, last, codeAt(t, secret, 1))
		return err
	}); err != nil {
		t.Fatalf("verify on the last try: %v", err)
	}
	if _, err := mfaSvc.ReserveAttempt(ctx, b.ID, PurposeFactorVerify); err != nil {
		t.Errorf("a try after a success: %v; want the tries given back", err)
	}
}

// TestStepUpGate checks that a route always needing a step-up refuses a
// session until it meets a second factor, that one needing it while a factor
// is held asks it only of someone holding one, and that a step-up belongs to
// its session alone.
func TestStepUpGate(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, tenant := member(t)
	signIn := func() *auth.TokenPair {
		t.Helper()
		pair, err := authSvc.IssuePair(ctx, a.ID, tenant, "192.0.2.1", "test", "password")
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		return pair
	}
	gate := mfaSvc.StepUpGate(map[string]StepUpRule{"POST /always": StepUpAlways, "POST /when-held": StepUpWhenFactorHeld})
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	serve := func(session uuid.UUID) http.Handler {
		p := dbtest.Principal(a.ID, tenant)
		p.SessionID = &session
		return dbtest.Serve(p, func(r chi.Router) {
			r.Use(gate)
			r.Post("/always", ok)
			r.Post("/when-held", ok)
			r.Post("/open", ok)
		})
	}
	expect := func(h http.Handler, path string, want int) {
		t.Helper()
		if rec := dbtest.Do(t, h, http.MethodPost, path, nil); rec.Code != want {
			t.Errorf("POST %s: %d %s; want %d", path, rec.Code, rec.Body.String(), want)
		}
	}

	session := signIn().SessionID
	h := serve(session)
	expect(h, "/open", http.StatusOK)
	expect(h, "/always", http.StatusForbidden)
	expect(h, "/when-held", http.StatusOK)

	enrolTOTP(t, mfaSvc, a)
	expect(h, "/when-held", http.StatusForbidden)
	if err := inTx(t, func(tx pgx.Tx) error { return mfaSvc.RecordVerification(ctx, tx, a.ID, session, "totp") }); err != nil {
		t.Fatalf("record step-up: %v", err)
	}
	expect(h, "/always", http.StatusOK)
	expect(h, "/when-held", http.StatusOK)
	expect(serve(signIn().SessionID), "/always", http.StatusForbidden)
}
