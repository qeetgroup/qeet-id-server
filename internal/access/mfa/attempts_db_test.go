//go:build integration

package mfa

import (
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestAttemptsAreLimited checks that a person gets five tries per purpose,
// that the limit of one purpose leaves another alone, and that a success
// gives the tries back.
func TestAttemptsAreLimited(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, _ := services(t, notifier.LogSender{})
	a, _ := member(t)
	for i := range maxMFAAttempts {
		if _, err := mfaSvc.reserveAttempt(ctx, a.ID, PurposeFactorVerify); err != nil {
			t.Fatalf("try %d: %v", i+1, err)
		}
	}
	if _, err := mfaSvc.reserveAttempt(ctx, a.ID, PurposeFactorVerify); !errors.Is(err, errs.ErrMFAAttemptsExceeded) {
		t.Errorf("a sixth try: %v; want %v", err, errs.ErrMFAAttemptsExceeded)
	}
	if _, err := mfaSvc.reserveAttempt(ctx, a.ID, PurposeOTPVerify); err != nil {
		t.Errorf("another purpose after the limit: %v; want allowed", err)
	}

	b, _ := member(t)
	secret, _ := enrolTOTP(t, mfaSvc, b)
	for range maxMFAAttempts - 1 {
		if _, err := mfaSvc.reserveAttempt(ctx, b.ID, PurposeFactorVerify); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := mfaSvc.Verify(ctx, b.ID, codeAt(t, secret, 1), self(b.ID)); err != nil {
		t.Fatalf("verify on the last try: %v", err)
	}
	if _, err := mfaSvc.reserveAttempt(ctx, b.ID, PurposeFactorVerify); err != nil {
		t.Errorf("a try after a success: %v; want the tries given back", err)
	}
}
