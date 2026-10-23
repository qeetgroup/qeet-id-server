//go:build integration

package mfa

import (
	"errors"
	"testing"
	"time"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// codeAt returns the TOTP code steps 30-second steps from now. A step a code
// was accepted in can't be used again, so each use needs a later step.
func codeAt(t *testing.T, secret string, steps int) string {
	t.Helper()
	code, err := totp.Code(secret, time.Now().Add(time.Duration(steps)*30*time.Second))
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	return code
}

// TestTOTPSignIn checks that once an authenticator app is set up, a password
// sign-in returns a challenge instead of tokens, a wrong code is refused, the
// right one completes the sign-in, and the challenge works once.
func TestTOTPSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, _ := member(t)
	secret, _ := enrolTOTP(t, mfaSvc, a)

	res, err := authSvc.Login(ctx, auth.LoginInput{Email: a.Email, Password: testPassword})
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
