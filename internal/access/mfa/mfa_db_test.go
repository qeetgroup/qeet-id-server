//go:build integration

package mfa

import (
	"errors"
	"testing"
	"time"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
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
	pool := dbtest.Pool(t)
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	mfaSvc := NewService(pool, "Qeet", notifier.LogSender{}, "")
	mfaSvc.SetCipher(box)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetMFA(mfaSvc)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	const password = "Kx7mQ2vLp9Wz"
	dbtest.SetPassword(t, a.ID, password)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	enrollment, err := mfaSvc.StartEnroll(ctx, tx, a.ID, a.Email)
	if err != nil {
		t.Fatalf("start enrolment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	attempt, err := mfaSvc.ReserveAttempt(ctx, a.ID, PurposeTOTPEnroll)
	if err != nil {
		t.Fatalf("reserve attempt: %v", err)
	}
	if tx, err = pool.Begin(ctx); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := mfaSvc.ConfirmEnroll(ctx, tx, attempt, codeAt(t, enrollment.Secret, 0)); err != nil {
		t.Fatalf("confirm enrolment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	res, err := authSvc.Login(ctx, auth.LoginInput{Email: a.Email, Password: password})
	if err != nil || !res.MFARequired || res.MFAToken == "" || res.Pair != nil {
		t.Fatalf("sign in: %+v, %v; want a challenge and no tokens", res, err)
	}
	wrong := "000000"
	if wrong == codeAt(t, enrollment.Secret, 1) {
		wrong = "111111"
	}
	if _, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, wrong, "", ""); err == nil {
		t.Fatal("a wrong code completed the sign-in")
	}
	pair, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, codeAt(t, enrollment.Secret, 1), "", "")
	if err != nil || pair.UserID != a.ID || pair.RefreshToken == "" {
		t.Fatalf("complete sign-in: %+v, %v", pair, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND second_factor = 'mfa'`, pair.SessionID); n != 1 {
		t.Error("the session doesn't record its second factor")
	}
	if _, err := authSvc.CompleteMFALogin(ctx, res.MFAToken, codeAt(t, enrollment.Secret, 1), "", ""); !errors.Is(err, errs.ErrAuthMFAChallengeExpired) {
		t.Errorf("second use of the challenge: %v, want %v", err, errs.ErrAuthMFAChallengeExpired)
	}
}
