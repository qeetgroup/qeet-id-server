//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
)

// A push approval request past its expiry reads as expired to everything that
// reads it, is recorded so, can no longer be answered, and is cleaned up.
func TestExpiredPushRequestReadsAsExpired(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	userID := createUserInTenant(t, ctx, createTenant(t, ctx, uniqueSlug("push-expiry")))
	_, deviceToken, err := svc.RegisterPushDevice(ctx, userID, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios")
	if err != nil {
		t.Fatal(err)
	}
	id, err := svc.CreatePushChallenge(ctx, userID, "sign_in", mfa.PushChallengeContext{})
	if err != nil {
		t.Fatal(err)
	}
	if ch, err := svc.GetPushChallenge(ctx, id); err != nil || ch.Status != "pending" {
		t.Fatalf("a live request: %+v %v, want pending", ch, err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_push_challenges SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	ch, err := svc.GetPushChallenge(ctx, id)
	if err != nil || ch.Status != "expired" {
		t.Fatalf("a request past its expiry: %+v %v, want expired", ch, err)
	}
	var stored string
	if err := testPool.QueryRow(ctx, `SELECT status FROM auth.mfa_push_challenges WHERE id = $1`, id).Scan(&stored); err != nil || stored != "expired" {
		t.Fatalf("stored status %q (%v), want expired", stored, err)
	}
	if err := svc.RespondToPushChallenge(ctx, id, userID, deviceToken, true); err == nil {
		t.Fatal("an expired request must not be approvable")
	}

	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_push_challenges SET expires_at = NOW() - INTERVAL '2 days' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if n, err := mfa.PurgeExpiredPushChallenges(ctx, testPool, mfa.OTPCodeRetention); err != nil || n < 1 {
		t.Fatalf("clean-up removed %d: %v", n, err)
	}
}
