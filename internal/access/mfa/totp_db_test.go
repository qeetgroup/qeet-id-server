//go:build integration

package mfa

import (
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

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

	fresh, err := mfaSvc.Regenerate(ctx, a.ID, self(a.ID))
	if err != nil {
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
	if err := mfaSvc.Disable(ctx, a.ID, self(a.ID)); err != nil {
		t.Fatalf("disable: %v", err)
	}
	res, err := authSvc.Login(ctx, authentication.LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || res.MFARequired || res.Pair == nil {
		t.Fatalf("sign in: %+v, %v; want tokens without a challenge", res, err)
	}
	if st, err := mfaSvc.RecoveryStatus(ctx, a.ID); err != nil || st.Enrolled || st.Total != 0 {
		t.Errorf("recovery codes after disabling: %+v, %v; want none", st, err)
	}
}

// TestFactorChangesCommitWithTheirAudit checks that a change to a person's
// second factors commits with its audit rows and the step-up it earns, each
// recorded as the caller's from where they made it, and that a change whose
// audit row can't be written leaves nothing behind and costs no attempt.
func TestFactorChangesCommitWithTheirAudit(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, organization := member(t)
	pair, err := authSvc.IssuePair(ctx, a.ID, organization, "192.0.2.1", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	by := Caller{Actor: audit.Actor{UserID: &a.ID, Type: "user", IP: "203.0.113.7", UserAgent: "mfa-test", RequestID: dbtest.Unique("request")},
		OrganizationID: &organization, SessionID: &pair.SessionID}
	recorded := func(action string) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND organization_id = $2 AND resource_id = $3
			AND actor_user_id = $3 AND actor_type = 'user' AND host(ip) = '203.0.113.7' AND user_agent = 'mfa-test' AND request_id = $4`,
			action, organization, a.ID, by.RequestID)
	}
	enrollment, err := mfaSvc.StartEnroll(ctx, a.ID, a.Email, by)
	if err != nil {
		t.Fatal(err)
	}
	if n := recorded("mfa.totp_enroll_started"); n != 1 {
		t.Errorf("the setup was recorded %d times as the caller's, want once", n)
	}

	unrecordable := by
	unrecordable.IP = "not an address"
	if _, err := mfaSvc.ConfirmEnroll(ctx, a.ID, codeAt(t, enrollment.Secret, 0), unrecordable); err == nil {
		t.Fatal("a confirmation whose audit row failed was accepted")
	}
	if enrolled, err := mfaSvc.IsEnrolled(ctx, a.ID); err != nil || enrolled {
		t.Errorf("after a confirmation that couldn't be audited the app is enrolled: %v, %v", enrolled, err)
	}
	if st, err := mfaSvc.StepUpState(ctx, a.ID, &pair.SessionID); err != nil || st.Met {
		t.Errorf("after a confirmation that couldn't be audited the session is stepped up: %+v, %v", st, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_recovery_codes WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d recovery codes minted by a confirmation that couldn't be audited", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND failed_attempts > 0`, a.ID); n != 0 {
		t.Error("a confirmation that failed to be audited cost an attempt")
	}

	if _, err := mfaSvc.ConfirmEnroll(ctx, a.ID, codeAt(t, enrollment.Secret, 0), by); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if n := recorded("mfa.totp_enrolled"); n != 1 {
		t.Errorf("the confirmation was recorded %d times as the caller's, want once", n)
	}
	if n := recorded("mfa.step_up_verified"); n != 1 {
		t.Errorf("the step-up was recorded %d times as the caller's, want once", n)
	}
	if st, err := mfaSvc.StepUpState(ctx, a.ID, &pair.SessionID); err != nil || !st.Met || st.Method != "totp" {
		t.Errorf("after confirming the app the session's step-up is %+v, %v; want met by totp", st, err)
	}
}

// TestTOTPSignIn checks that once an authenticator app is set up, a password
// sign-in returns a challenge instead of tokens, a wrong code is refused, the
// right one completes the sign-in, and the challenge works once.
func TestTOTPSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, _ := member(t)
	secret, _ := enrolTOTP(t, mfaSvc, a)

	res, err := authSvc.Login(ctx, authentication.LoginInput{Email: a.Email, Password: testPassword})
	if err != nil || !res.MFARequired || res.MFAToken == "" || res.Pair != nil {
		t.Fatalf("sign in: %+v, %v; want a challenge and no tokens", res, err)
	}
	wrong := "000000"
	if wrong == codeAt(t, secret, 1) {
		wrong = "111111"
	}
	if _, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, wrong, "", ""); err == nil {
		t.Fatal("a wrong code completed the sign-in")
	}
	pair, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, codeAt(t, secret, 1), "", "")
	if err != nil || pair.UserID != a.ID || pair.RefreshToken == "" {
		t.Fatalf("complete sign-in: %+v, %v", pair, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND second_factor = 'mfa'`, pair.SessionID); n != 1 {
		t.Error("the session doesn't record its second factor")
	}
	if _, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, codeAt(t, secret, 1), "", ""); !errors.Is(err, errs.ErrAuthMFAChallengeExpired) {
		t.Errorf("second use of the challenge: %v, want %v", err, errs.ErrAuthMFAChallengeExpired)
	}
}
