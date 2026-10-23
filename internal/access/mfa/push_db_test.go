//go:build integration

package mfa

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// expo is a fake Expo push service: it records each message's challenge and
// answers DeviceNotRegistered for a push token containing "gone".
type expo struct {
	*httptest.Server
	mu         sync.Mutex
	challenges []string
}

func newExpo(t *testing.T) *expo {
	e := &expo{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var msgs []struct {
			To   string `json:"to"`
			Data struct {
				ChallengeID string `json:"challenge_id"`
			} `json:"data"`
		}
		_ = json.Unmarshal(body, &msgs)
		e.mu.Lock()
		for _, m := range msgs {
			e.challenges = append(e.challenges, m.Data.ChallengeID)
		}
		e.mu.Unlock()
		if len(msgs) == 1 && strings.Contains(msgs[0].To, "gone") {
			_, _ = w.Write([]byte(`{"data":[{"status":"error","message":"gone","details":{"error":"DeviceNotRegistered"}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[{"status":"ok","id":"ticket"}]}`))
	}))
	t.Cleanup(e.Close)
	return e
}

func (e *expo) sent() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.challenges...)
}

// pushServices returns MFA and authentication services that deliver push
// requests to push.
func pushServices(t *testing.T, push *expo) (*Service, *auth.Service) {
	t.Helper()
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	mfaSvc.pushURL = push.URL
	return mfaSvc, authSvc
}

// TestPushApproval checks that a phone linked with a pairing code receives a
// request, that only it can answer, that an answer is final, that an
// unanswered request expires, and that a phone the app is gone from is retired.
func TestPushApproval(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newExpo(t)
	svc, _ := pushServices(t, push)
	a, tenant := member(t)
	other, _ := member(t)

	pairing, code, err := svc.CreatePushPairing(ctx, a.ID, &tenant, "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	claim, err := svc.ClaimPushPairing(ctx, code, "Phone", "ExponentPushToken[ok]", "ios", "192.0.2.2", "app")
	if err != nil || claim.UserID != a.ID || claim.DeviceToken == "" {
		t.Fatalf("claim: %+v, %v; want a device linked to the account", claim, err)
	}
	if _, err := svc.ClaimPushPairing(ctx, code, "Phone", "ExponentPushToken[ok2]", "ios", "", ""); !errors.Is(err, errs.ErrMFAPairingCodeInvalid) {
		t.Errorf("a used pairing code: %v, want %v", err, errs.ErrMFAPairingCodeInvalid)
	}
	if got, err := svc.GetPushPairing(ctx, a.ID, pairing.ID); err != nil || got.DeviceID == nil || *got.DeviceID != claim.Device.ID {
		t.Errorf("pairing after the claim: %+v, %v; want it to name the device", got, err)
	}

	challenge := func() uuid.UUID {
		t.Helper()
		id, err := svc.CreatePushChallenge(ctx, a.ID, "sign_in", PushChallengeContext{IP: "192.0.2.1"})
		if err != nil {
			t.Fatalf("push request: %v", err)
		}
		return id
	}
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
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, "not-the-device", true); !errors.Is(err, errs.ErrMFAPushUnauthorized) {
		t.Errorf("an answer from another device: %v, want %v", err, errs.ErrMFAPushUnauthorized)
	}
	if err := svc.RespondToPushChallenge(ctx, approved, other.ID, claim.DeviceToken, true); err == nil {
		t.Error("another account answered the request")
	}
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, claim.DeviceToken, true); err != nil || status(approved) != "approved" {
		t.Fatalf("approve: %v, status %q", err, status(approved))
	}
	if err := svc.RespondToPushChallenge(ctx, approved, a.ID, claim.DeviceToken, false); err == nil || status(approved) != "approved" {
		t.Errorf("a second answer: %v, status %q; want it refused and the first to stand", err, status(approved))
	}

	denied := challenge()
	if err := svc.RespondToPushChallenge(ctx, denied, a.ID, claim.DeviceToken, false); err != nil || status(denied) != "denied" {
		t.Errorf("deny: %v, status %q", err, status(denied))
	}
	stale := challenge()
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.mfa_push_challenges SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, stale); err != nil {
		t.Fatal(err)
	}
	if status(stale) != "expired" {
		t.Errorf("an unanswered request past its time: %q, want expired", status(stale))
	}

	b, _ := member(t)
	if _, _, err := svc.RegisterPushDevice(ctx, b.ID, "Old phone", "ExponentPushToken[gone]", "android"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePushChallenge(ctx, b.ID, "sign_in", PushChallengeContext{}); !errors.Is(err, errs.ErrMFAPushDeliveryFailed) {
		t.Errorf("a request to a phone the app is gone from: %v, want %v", err, errs.ErrMFAPushDeliveryFailed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_push_devices WHERE user_id = $1 AND device_token_expires_at > NOW()`, b.ID); n != 0 {
		t.Error("the gone phone was not retired")
	}
}

// TestPushSignIn checks that a sign-in waits on the phone and completes once
// the request is approved there.
func TestPushSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newExpo(t)
	svc, authSvc := pushServices(t, push)
	a, _ := member(t)
	_, device, err := svc.RegisterPushDevice(ctx, a.ID, "Phone", "ExponentPushToken[ok]", "ios")
	if err != nil {
		t.Fatal(err)
	}
	token := challenge(t, authSvc, a)
	if _, err := authSvc.StartMFAPush(ctx, token, "192.0.2.1", "test"); err != nil {
		t.Fatalf("start push: %v", err)
	}
	if _, _, err := authSvc.CompleteMFALoginWith(ctx, token, auth.MFAProof{Push: true}, "", ""); !errors.Is(err, errs.ErrMFAPushPending) {
		t.Errorf("complete before the phone answers: %v, want %v", err, errs.ErrMFAPushPending)
	}
	sent := push.sent()
	if len(sent) != 1 {
		t.Fatalf("delivered %d requests, want 1", len(sent))
	}
	if err := svc.RespondToPushChallenge(ctx, uuid.MustParse(sent[0]), a.ID, device, true); err != nil {
		t.Fatalf("approve on the phone: %v", err)
	}
	pair, _, err := authSvc.CompleteMFALoginWith(ctx, token, auth.MFAProof{Push: true}, "", "")
	if err != nil || pair == nil || pair.UserID != a.ID {
		t.Fatalf("complete after approval: %+v, %v", pair, err)
	}
}

// TestPushStepUp checks that approving a step-up request on a linked phone
// steps the calling session up, and not before.
func TestPushStepUp(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newExpo(t)
	svc, authSvc := pushServices(t, push)
	a, tenant := member(t)
	_, device, err := svc.RegisterPushDevice(ctx, a.ID, "Phone", "ExponentPushToken[ok]", "ios")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := authSvc.IssuePair(ctx, a.ID, tenant, "192.0.2.1", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	p := dbtest.Principal(a.ID, tenant)
	p.SessionID = &pair.SessionID
	h := dbtest.Serve(p, (&Handler{Service: svc}).Mount)

	rec := dbtest.Do(t, h, http.MethodPost, "/mfa/push/step-up", nil)
	var started struct {
		ChallengeID uuid.UUID `json:"challenge_id"`
	}
	dbtest.Decode(t, rec, &started)
	if rec.Code != http.StatusAccepted || started.ChallengeID == uuid.Nil {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	complete := "/mfa/push/step-up/" + started.ChallengeID.String() + "/complete"
	if rec := dbtest.Do(t, h, http.MethodPost, complete, nil); rec.Code != http.StatusConflict {
		t.Errorf("complete before the phone answers: %d, want 409", rec.Code)
	}
	if err := svc.RespondToPushChallenge(ctx, started.ChallengeID, a.ID, device, true); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, complete, nil); rec.Code/100 != 2 {
		t.Fatalf("complete after approval: %d %s", rec.Code, rec.Body.String())
	}
	if st, err := svc.StepUpState(ctx, a.ID, &pair.SessionID); err != nil || !st.Met || st.Method != "push" {
		t.Errorf("step-up after approval: %+v, %v; want met by push", st, err)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, complete, nil); rec.Code/100 == 2 {
		t.Error("a spent step-up request completed again")
	}
}
