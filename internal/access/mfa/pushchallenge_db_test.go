//go:build integration

package mfa

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPushApproval checks that a phone linked with a pairing code receives a
// request, that only it can answer, that an answer is final, that an
// unanswered request expires, and that a phone the app is gone from is retired.
func TestPushApproval(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newPhones(t)
	svc, _ := pushServices(t, push)
	a, organization := member(t)
	other, _ := member(t)

	pairing, code, err := svc.CreatePushPairing(ctx, a.ID, Caller{Actor: audit.Actor{IP: "192.0.2.1", UserAgent: "test"}, OrganizationID: &organization})
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	claim, err := svc.ClaimPushPairing(ctx, code, "Phone", "fcm-ok", "android", audit.Actor{IP: "192.0.2.2", UserAgent: "app"})
	if err != nil || claim.UserID != a.ID || claim.DeviceToken == "" {
		t.Fatalf("claim: %+v, %v; want a device linked to the account", claim, err)
	}
	if _, err := svc.ClaimPushPairing(ctx, code, "Phone", "fcm-ok2", "android", audit.Actor{}); !errors.Is(err, ErrPairingCodeInvalid) {
		t.Errorf("a used pairing code: %v, want %v", err, ErrPairingCodeInvalid)
	}
	if got, err := svc.GetPushPairing(ctx, a.ID, pairing.ID); err != nil || got.DeviceID == nil || *got.DeviceID != claim.Device.ID {
		t.Errorf("pairing after the claim: %+v, %v; want it to name the device", got, err)
	}
	// The pairing is recorded as the person's, the link as the phone's, each
	// from where it was made.
	for _, want := range []struct {
		action, actorType, ip, ua string
		resource                  uuid.UUID
	}{
		{"mfa.push_pairing_created", "user", "192.0.2.1", "test", pairing.ID},
		{"mfa.push_device_linked", "device", "192.0.2.2", "app", claim.Device.ID},
	} {
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = $1 AND organization_id = $2
			AND actor_type = $3 AND actor_user_id = $4 AND host(ip) = $5 AND user_agent = $6 AND resource_id = $7`,
			want.action, organization, want.actorType, a.ID, want.ip, want.ua, want.resource); n != 1 {
			t.Errorf("%s recorded %d times as %s from %s, want once", want.action, n, want.actorType, want.ip)
		}
	}

	numbers := map[uuid.UUID]int{}
	challengeFor := func(userID uuid.UUID) uuid.UUID {
		t.Helper()
		id, number, err := svc.CreatePushChallenge(ctx, userID, "sign_in", PushChallengeContext{IP: "192.0.2.1"})
		if err != nil || number < 10 || number > 99 {
			t.Fatalf("push request: number %d, %v; want a two-digit number", number, err)
		}
		numbers[id] = number
		return id
	}
	challenge := func() uuid.UUID { return challengeFor(a.ID) }
	status := func(id uuid.UUID) string {
		t.Helper()
		ch, err := svc.GetPushChallenge(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return ch.Status
	}

	approved := challenge()
	if sent := push.sent(); len(sent) != 1 || sent[0] != approved.String() {
		t.Fatalf("delivered %v, want the request %s", sent, approved)
	}
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, "not-the-device", true, numbers[approved]); !errors.Is(err, ErrPushUnauthorized) {
		t.Errorf("an answer from another device: %v, want %v", err, ErrPushUnauthorized)
	}
	if err := svc.RespondToPushChallenge(ctx, approved, other.ID, claim.DeviceToken, true, numbers[approved]); err == nil {
		t.Error("another account answered the request")
	}
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, claim.DeviceToken, true, numbers[approved]); err != nil || status(approved) != "approved" {
		t.Fatalf("approve: %v, status %q", err, status(approved))
	}
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, claim.DeviceToken, false, 0); err == nil || status(approved) != "approved" {
		t.Errorf("a second answer: %v, status %q; want it refused and the first to stand", err, status(approved))
	}

	denied := challenge()
	if err := svc.RespondToPushChallenge(ctx, denied, a.ID, claim.DeviceToken, false, 0); err != nil || status(denied) != "denied" {
		t.Errorf("deny: %v, status %q", err, status(denied))
	}
	guessed := challenge()
	if err := svc.RespondToPushChallenge(ctx, guessed, a.ID, claim.DeviceToken, true, 109-numbers[guessed]); !errors.Is(err, ErrPushNumberMismatch) || status(guessed) != "denied" {
		t.Errorf("approve with another number: %v, status %q; want %v and denied", err, status(guessed), ErrPushNumberMismatch)
	}
	stale := challenge()
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_push_challenges SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	if status(stale) != "expired" {
		t.Errorf("an unanswered request past its time: %q, want expired", status(stale))
	}
	challenge() // the fifth in ten minutes
	if _, _, err := svc.CreatePushChallenge(ctx, a.ID, "sign_in", PushChallengeContext{}); !errors.Is(err, ErrPushLimited) {
		t.Errorf("a sixth request in ten minutes: %v, want %v", err, ErrPushLimited)
	}
	c, _ := member(t)
	_, cDevice, err := svc.RegisterPushDevice(ctx, c.ID, "Phone", "fcm-ok-c", "android")
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := svc.RespondToPushChallenge(ctx, challengeFor(c.ID), c.ID, cDevice, false, 0); err != nil {
			t.Fatalf("deny: %v", err)
		}
	}
	if _, _, err := svc.CreatePushChallenge(ctx, c.ID, "sign_in", PushChallengeContext{}); !errors.Is(err, ErrPushLimited) {
		t.Errorf("a request after three denials this hour: %v, want %v", err, ErrPushLimited)
	}

	b, _ := member(t)
	if _, _, err := svc.RegisterPushDevice(ctx, b.ID, "Old phone", "fcm-gone", "android"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreatePushChallenge(ctx, b.ID, "sign_in", PushChallengeContext{}); !errors.Is(err, ErrPushDeliveryFailed) {
		t.Errorf("a request to a phone the app is gone from: %v, want %v", err, ErrPushDeliveryFailed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1 AND device_token_expires_at > NOW()`, b.ID); n != 0 {
		t.Error("the gone phone was not retired")
	}
}
