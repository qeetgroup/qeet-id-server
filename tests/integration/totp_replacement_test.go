//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Setting up a new authenticator app while one is confirmed needs a step-up,
// and the new app waits beside the confirmed one: the confirmed app keeps
// signing in until a code from the new one confirms it, and a setup left
// unconfirmed is ignored. Asking for a new code to an email or SMS factor
// already confirmed no longer takes that factor away.

// holdApp gives userID a confirmed authenticator app and returns its secret.
func holdApp(t *testing.T, ctx context.Context, svc *mfa.Service, userID uuid.UUID) string {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := svc.StartEnroll(ctx, tx, userID, "app@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := mfaConfirmEnroll(ctx, svc, userID, totpCodeAtStep(t, e.Secret, -1)); err != nil {
		t.Fatal(err)
	}
	return e.Secret
}

// startApp starts setting up a (new) authenticator app through the service.
func startApp(t *testing.T, ctx context.Context, svc *mfa.Service, userID uuid.UUID) *mfa.Enrollment {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	e, err := svc.StartEnroll(ctx, tx, userID, "app@example.com")
	if err != nil {
		t.Fatalf("start enroll: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestReplacingTheAppNeedsAStepUp: with a confirmed app, starting a new setup
// is refused until the calling session steps up, and is audited as a
// replacement; a first setup needs no step-up.
func TestReplacingTheAppNeedsAStepUp(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	tenantID := createTenant(t, ctx, uniqueSlug("replace"))
	holder, newcomer := createUserInTenant(t, ctx, tenantID), createUserInTenant(t, ctx, tenantID)
	holdApp(t, ctx, svc, holder)
	holderSess, newcomerSess := openSession(t, ctx, holder, tenantID), openSession(t, ctx, newcomer, tenantID)

	start := func(userID, sess uuid.UUID) (int, mfa.Enrollment) {
		r := chi.NewRouter()
		r.Group(func(r chi.Router) {
			r.Use(withSessionPrincipal(userID, tenantID, sess))
			(&mfa.Handler{Service: svc}).Mount(r)
		})
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mfa/totp/enroll/start", bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		var e mfa.Enrollment
		_ = json.Unmarshal(rr.Body.Bytes(), &e)
		return rr.Code, e
	}

	if code, _ := start(holder, holderSess); code != http.StatusForbidden {
		t.Fatalf("replacing a confirmed app without a step-up = %d, want 403", code)
	}
	if code, e := start(newcomer, newcomerSess); code != http.StatusOK || e.Replacing {
		t.Fatalf("a first setup = %d (replacing %v), want 200 with no step-up", code, e.Replacing)
	}
	recordStepUp(t, ctx, svc, holder, holderSess, "totp")
	code, e := start(holder, holderSess)
	if code != http.StatusOK || !e.Replacing || e.Secret == "" {
		t.Fatalf("replacing after a step-up = %d %+v, want 200 replacing", code, e)
	}
	var replacing bool
	if err := testPool.QueryRow(ctx, `
		SELECT (metadata->>'replacing')::bool FROM audit.events
		WHERE actor_user_id = $1 AND action = 'mfa.totp_enroll_started'
		ORDER BY created_at DESC LIMIT 1`, holder).Scan(&replacing); err != nil || !replacing {
		t.Fatalf("the start of a replacement must be audited as one (replacing=%v err=%v)", replacing, err)
	}
}

// TestAbandonedReplacementKeepsTheApp: a replacement started and never
// confirmed leaves the confirmed app in place: sign-in still asks for it and
// accepts its code.
func TestAbandonedReplacementKeepsTheApp(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	me, email := f.member(t, ctx)
	current := f.holdTOTP(t, ctx, me)

	if e := startApp(t, ctx, f.mfa, me); !e.Replacing {
		t.Fatal("a setup started beside a confirmed app must report that it replaces it")
	}
	if enrolled, err := f.mfa.IsEnrolled(ctx, me); err != nil || !enrolled {
		t.Fatalf("an unconfirmed replacement must not switch the confirmed app off (enrolled=%v err=%v)", enrolled, err)
	}
	c := f.signIn(t, email)
	if !c.MFARequired {
		t.Fatal("sign-in must still ask for the second factor while a replacement waits")
	}
	if rr, _ := f.complete(map[string]any{"mfa_token": c.MFAToken, "code": totpCodeAtStep(t, current, 1)}); rr.Code != http.StatusOK {
		t.Fatalf("the confirmed app's code must still sign in: %d %s", rr.Code, rr.Body.String())
	}
}

// TestConfirmingTheReplacementSwitchesApps: a code from the new app makes it
// the account's app, with fresh recovery codes; the old app's codes stop
// working.
func TestConfirmingTheReplacementSwitchesApps(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("switch")))
	old := holdApp(t, ctx, svc, userID)
	next := startApp(t, ctx, svc, userID)

	if _, err := mfaConfirmEnroll(ctx, svc, userID, totpCodeAtStep(t, old, 0)); err == nil {
		t.Fatal("a code from the old app must not confirm the new one")
	}
	codes, err := mfaConfirmEnroll(ctx, svc, userID, totpCodeAtStep(t, next.Secret, 0))
	if err != nil || len(codes) != 10 {
		t.Fatalf("confirming the new app: %v (%d codes)", err, len(codes))
	}
	if _, err := mfaVerify(ctx, svc, userID, totpCodeAtStep(t, old, 1)); err == nil {
		t.Fatal("the replaced app's codes must stop working")
	}
	if _, err := mfaVerify(ctx, svc, userID, totpCodeAtStep(t, next.Secret, 1)); err != nil {
		t.Fatalf("the new app's codes must work: %v", err)
	}
}

// TestExpiredReplacementIsIgnored: a replacement not confirmed within its
// time is refused and the confirmed app stays.
func TestExpiredReplacementIsIgnored(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("expire")))
	old := holdApp(t, ctx, svc, userID)
	next := startApp(t, ctx, svc, userID)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_totp SET pending_started_at = NOW() - INTERVAL '31 minutes' WHERE user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	_, err := mfaConfirmEnroll(ctx, svc, userID, totpCodeAtStep(t, next.Secret, 0))
	if !errors.Is(err, errs.ErrMFAEnrollNotStarted) {
		t.Fatalf("an expired replacement must be refused as not started, got %v", err)
	}
	if _, err := mfaVerify(ctx, svc, userID, totpCodeAtStep(t, old, 0)); err != nil {
		t.Fatalf("the confirmed app must keep working after a replacement expires: %v", err)
	}
}

// TestNewCodeKeepsAnEmailFactor: asking for a new code to an email address
// already confirmed as a factor leaves that factor confirmed.
func TestNewCodeKeepsAnEmailFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	sender := &captureSender{}
	svc := mfa.NewService(testPool, "qeet-test", sender, "")
	svc.SetCipher(testEnvelope(t))
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("email-factor")))
	address := uniqueSlug("factor") + "@example.com"

	factorID, err := svc.EnrollOTPStart(ctx, userID, nil, "email", address)
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := sender.last()
	if err := mfaEnrollOTPConfirm(ctx, svc, userID, factorID, sixDigits.FindString(msg.Body)); err != nil {
		t.Fatalf("confirm email factor: %v", err)
	}
	allowNextCode(t, ctx, factorID)
	again, err := svc.EnrollOTPStart(ctx, userID, nil, "email", address)
	if err != nil || again != factorID {
		t.Fatalf("asking again for the same address: %v (factor %v, want %v)", err, again, factorID)
	}
	factors, err := svc.ListOTPFactors(ctx, userID)
	if err != nil || len(factors) != 1 || !factors[0].Verified {
		t.Fatalf("the confirmed email factor must stay confirmed: %+v %v", factors, err)
	}
}
