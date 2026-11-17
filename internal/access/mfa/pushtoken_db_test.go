//go:build integration

package mfa

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestNativeAppLinkAndTokenRotation checks what the native apps rely on: the pairing claim
// names the account, a linked phone replaces its rotated push token with its current
// device credential only, once per phone, and it can list the requests waiting on it.
func TestNativeAppLinkAndTokenRotation(t *testing.T) {
	ctx := dbtest.Context(t)
	svc, _ := pushServices(t, newExpo(t))
	a, organization := member(t)

	link := func(pushToken string) PushPairingClaim {
		t.Helper()
		_, code, err := svc.CreatePushPairing(ctx, a.ID, &organization, "192.0.2.1", "test")
		if err != nil {
			t.Fatalf("pairing: %v", err)
		}
		claim, err := svc.ClaimPushPairing(ctx, code, "Meera's iPhone", pushToken, "ios", "192.0.2.2", "app")
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		return claim
	}
	stored := func() []string {
		t.Helper()
		var tokens []string
		_ = inTx(t, func(tx pgx.Tx) error {
			targets, err := svc.loadPushTokens(ctx, tx, a.ID)
			for _, target := range targets {
				tokens = append(tokens, target.token)
			}
			return err
		})
		return tokens
	}

	claim := link("a1b2c3d4")
	if claim.Account == nil || claim.Account.Email != a.Email {
		t.Fatalf("claim account = %+v, want %s", claim.Account, a.Email)
	}

	// The device credential replaces the token; nothing else does.
	if err := svc.UpdatePushToken(ctx, claim.Device.ID, a.ID, "not-the-credential", "e5f6"); !errors.Is(err, errs.ErrMFAPushUnauthorized) {
		t.Errorf("wrong credential: %v, want %v", err, errs.ErrMFAPushUnauthorized)
	}
	if err := svc.UpdatePushToken(ctx, claim.Device.ID, a.ID, claim.DeviceToken, "e5f6"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := stored(); len(got) != 1 || got[0] != "e5f6" {
		t.Errorf("stored tokens = %v, want [e5f6]", got)
	}

	// A second link already holding the new token is folded into this one.
	second := link("0a0b")
	if err := svc.UpdatePushToken(ctx, claim.Device.ID, a.ID, claim.DeviceToken, "0a0b"); err != nil {
		t.Fatalf("update to a token another link holds: %v", err)
	}
	if got := stored(); len(got) != 1 || got[0] != "0a0b" {
		t.Errorf("stored tokens = %v, want the one phone once", got)
	}
	if err := svc.UpdatePushToken(ctx, second.Device.ID, a.ID, second.DeviceToken, "ffff"); !errors.Is(err, errs.ErrMFAPushUnauthorized) {
		t.Errorf("the folded link still updates: %v", err)
	}

	// An expired credential can't keep a phone receiving requests.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_push_devices SET device_token_expires_at = NOW() - interval '1 second' WHERE id = $1`, claim.Device.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdatePushToken(ctx, claim.Device.ID, a.ID, claim.DeviceToken, "abcd"); !errors.Is(err, errs.ErrMFAPushUnauthorized) {
		t.Errorf("expired credential: %v, want %v", err, errs.ErrMFAPushUnauthorized)
	}

	// Over HTTP, as the app calls it: no session, the credential in the body.
	fresh := link("1234")
	h := dbtest.Serve(nil, (&Handler{Service: svc}).MountPublic)
	path := "/mfa/push/devices/" + fresh.Device.ID.String() + "/push-token"
	if rec := dbtest.Do(t, h, http.MethodPost, path, map[string]any{"user_id": a.ID, "device_token": fresh.DeviceToken, "push_token": "5678"}); rec.Code != http.StatusNoContent {
		t.Errorf("POST push-token: %d %s, want 204", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, h, http.MethodPost, path, map[string]any{"user_id": a.ID, "device_token": fresh.DeviceToken}); rec.Code != http.StatusBadRequest {
		t.Errorf("POST push-token without push_token: %d, want 400", rec.Code)
	}

	// The iOS phone's push service has no credentials here (only Expo is configured), so the
	// request stays open for the app to find when it opens, rather than failing the sign-in.
	challengeID, _, err := svc.CreatePushChallenge(ctx, a.ID, "sign_in", PushChallengeContext{IP: "198.51.100.7"})
	if err != nil {
		t.Fatalf("a request to a phone whose push service is not configured: %v", err)
	}
	pending := "/mfa/push/devices/" + fresh.Device.ID.String() + "/pending"
	rec := dbtest.Do(t, h, http.MethodPost, pending, map[string]any{"user_id": a.ID, "device_token": fresh.DeviceToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST pending: %d %s, want 200", rec.Code, rec.Body.String())
	}
	var list struct {
		Challenges []PushChallenge `json:"challenges"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Challenges) != 1 || list.Challenges[0].ID != challengeID || list.Challenges[0].Status != "pending" {
		t.Errorf("pending = %+v, want the one request", list.Challenges)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, pending, map[string]any{"user_id": a.ID, "device_token": "not-the-credential"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("POST pending with the wrong credential: %d, want 401", rec.Code)
	}
	b, _ := member(t)
	if _, err := svc.PendingPushChallenges(ctx, fresh.Device.ID, b.ID, fresh.DeviceToken); !errors.Is(err, errs.ErrMFAPushUnauthorized) {
		t.Errorf("another account's id with this phone's credential: %v, want %v", err, errs.ErrMFAPushUnauthorized)
	}

	// An answered request is no longer pending.
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_push_challenges SET status = 'denied' WHERE id = $1`, challengeID); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.PendingPushChallenges(ctx, fresh.Device.ID, a.ID, fresh.DeviceToken); err != nil || len(got) != 0 {
		t.Errorf("pending after an answer = %v, %v, want none", got, err)
	}
}
