//go:build integration

package mfa

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestWrongCodesInARowLockSignIn checks that a long run of wrong second
// factors locks second-factor sign-in, even with the right code after, tells
// the person, and that ending their sign-ins, as a password reset does, lifts
// the lock while a right code ends a shorter run.
func TestWrongCodesInARowLockSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	mail := &dbtest.Mailbox{}
	mfaSvc, authSvc := services(t, notifier.LogSender{}, func(d *auth.Deps) { d.Sender = mail })
	a, _ := member(t)
	secret, recovery := enrolTOTP(t, mfaSvc, a)
	run := func(failures int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			INSERT INTO auth.mfa_failure_streaks (user_id, failures) VALUES ($1, $2)
			ON CONFLICT (user_id) DO UPDATE SET failures = EXCLUDED.failures, locked_at = NULL
		`, a.ID, failures); err != nil {
			t.Fatal(err)
		}
	}
	wrong := "000000"
	if wrong == codeAt(t, secret, 1) {
		wrong = "111111"
	}

	run(10)
	if pair, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), codeAt(t, secret, 1), "", ""); err != nil || pair == nil {
		t.Fatalf("the right code after ten wrong: %v", err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_failure_streaks WHERE user_id = $1`, a.ID); n != 0 {
		t.Error("a right code did not end the run")
	}

	run(49)
	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), wrong, "", ""); !errors.Is(err, errs.ErrMFALocked) {
		t.Fatalf("the fiftieth wrong code in a row: %v, want %v", err, errs.ErrMFALocked)
	}
	if msg := mail.Last(t); msg.To != a.Email || !strings.Contains(msg.Subject, "locked") {
		t.Errorf("mail %q to %s; want the person told of the lock", msg.Subject, msg.To)
	}
	if _, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), recovery[0], "", ""); !errors.Is(err, errs.ErrMFALocked) {
		t.Errorf("the right code once locked: %v, want %v", err, errs.ErrMFALocked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.mfa_locked' AND resource_id = $1`, a.ID); n != 1 {
		t.Errorf("%d auth.mfa_locked records, want 1", n)
	}

	if err := inTx(t, func(tx pgx.Tx) error {
		_, err := auth.EndSignIns(ctx, tx, nil, a.ID, "password_reset")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if pair, err := authSvc.CompleteMFALogin(ctx, challenge(t, authSvc, a), recovery[0], "", ""); err != nil || pair == nil {
		t.Errorf("the right code after the sign-ins were ended: %v", err)
	}
}

// TestPushSignIn checks that a sign-in waits on the phone and completes once
// the request is approved there.
func TestPushSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newPhones(t)
	svc, authSvc := pushServices(t, push)
	a, _ := member(t)
	_, device, err := svc.RegisterPushDevice(ctx, a.ID, "Phone", "fcm-ok", "android")
	if err != nil {
		t.Fatal(err)
	}
	token := challenge(t, authSvc, a)
	_, number, err := authSvc.StartMFAPush(ctx, token, "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("start push: %v", err)
	}
	if _, _, err := authSvc.CompleteMFALoginWith(ctx, token, auth.MFAProof{Push: true}, "", ""); !errors.Is(err, errs.ErrMFAPushPending) {
		t.Errorf("complete before the phone answers: %v, want %v", err, errs.ErrMFAPushPending)
	}
	sent := push.sent()
	if len(sent) != 1 {
		t.Fatalf("delivered %d requests, want 1", len(sent))
	}
	if err := svc.RespondToPushChallenge(ctx, uuid.MustParse(sent[0]), a.ID, device, true, number); err != nil {
		t.Fatalf("approve on the phone: %v", err)
	}
	pair, _, err := authSvc.CompleteMFALoginWith(ctx, token, auth.MFAProof{Push: true}, "", "")
	if err != nil || pair == nil || pair.UserID != a.ID {
		t.Fatalf("complete after approval: %+v, %v", pair, err)
	}
}
