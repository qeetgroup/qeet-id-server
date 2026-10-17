//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// A one-time code that cannot be delivered is never reported as sent: a
// channel with no way to reach anyone is refused before anything is stored,
// and a provider that fails gives a delivery error and leaves no usable code.

type failingSender struct{}

func (failingSender) Send(context.Context, notifier.Message) error {
	return errors.New("provider down")
}

func codeRows(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
		WHERE f.user_id = $1`, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestUndeliverableChannelIsRefused: with no SMS provider, setting up and
// challenging an SMS factor are refused with a clear reason, and no factor or
// code is stored; email, which can deliver, works as before.
func TestUndeliverableChannelIsRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	sender := &captureSender{}
	svc := mfa.NewService(testPool, "qeet-test", sender, "")
	svc.SetCipher(testEnvelope(t))
	svc.SetDeliveryCheck(notifier.Router{Email: sender, Default: notifier.LogSender{}}.Configured)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("deliver")))

	if _, err := svc.EnrollOTPStart(ctx, userID, nil, "sms", "+15550123"); !errors.Is(err, errs.ErrMFADeliveryUnavailable) {
		t.Fatalf("setting up SMS with no SMS provider: %v, want %s", err, errs.CodeMFADeliveryUnavailable)
	}
	if factors, _ := svc.ListOTPFactors(ctx, userID); len(factors) != 0 {
		t.Fatalf("a refused setup must store no factor, found %d", len(factors))
	}
	var smsFactor uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at)
		VALUES ($1, 'sms', '+15550124', NOW()) RETURNING id`, userID).Scan(&smsFactor); err != nil {
		t.Fatal(err)
	}
	if err := svc.SendLoginCode(ctx, userID, nil, smsFactor); !errors.Is(err, errs.ErrMFADeliveryUnavailable) {
		t.Fatalf("an SMS sign-in code with no SMS provider: %v, want %s", err, errs.CodeMFADeliveryUnavailable)
	}
	if n := codeRows(t, ctx, userID); n != 0 {
		t.Fatalf("a refused send must store no code, found %d", n)
	}
	if _, err := svc.EnrollOTPStart(ctx, userID, nil, "email", uniqueSlug("deliver")+"@example.com"); err != nil {
		t.Fatalf("email, which can deliver: %v", err)
	}
}

// TestFailedDeliveryLeavesNoCode: when the provider fails, the caller gets a
// delivery error, the code is withdrawn so it neither works nor counts against
// a limit, and the failure is audited.
func TestFailedDeliveryLeavesNoCode(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := mfa.NewService(testPool, "qeet-test", failingSender{}, "")
	svc.SetCipher(testEnvelope(t))
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("deliver-fail")))
	var factorID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.mfa_otp_factors (user_id, channel, destination, verified_at)
		VALUES ($1, 'email', $2, NOW()) RETURNING id`, userID, uniqueSlug("fail")+"@example.com").Scan(&factorID); err != nil {
		t.Fatal(err)
	}
	if err := svc.ChallengeOTP(ctx, userID, nil, factorID); !errors.Is(err, errs.ErrMFADeliveryFailed) {
		t.Fatalf("a failing provider: %v, want %s", err, errs.CodeMFADeliveryFailed)
	}
	if n := codeRows(t, ctx, userID); n != 0 {
		t.Fatalf("an undelivered code must be withdrawn, found %d", n)
	}
	if err := svc.ChallengeOTP(ctx, userID, nil, factorID); !errors.Is(err, errs.ErrMFADeliveryFailed) {
		t.Fatalf("a retry must reach the provider again, not wait out a limit: %v", err)
	}
	var audited int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'mfa.otp_delivery_failed'`, userID).
		Scan(&audited); err != nil || audited != 2 {
		t.Fatalf("each failed delivery must be audited, found %d (%v)", audited, err)
	}
}
