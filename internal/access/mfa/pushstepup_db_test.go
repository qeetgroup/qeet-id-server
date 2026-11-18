//go:build integration

package mfa

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestPushStepUp checks that approving a step-up request on a linked phone
// steps the calling session up, and not before.
func TestPushStepUp(t *testing.T) {
	ctx := dbtest.Context(t)
	push := newPhones(t)
	svc, authSvc := pushServices(t, push)
	a, organization := member(t)
	_, device, err := svc.RegisterPushDevice(ctx, a.ID, "Phone", "fcm-ok", "android")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := authSvc.IssuePair(ctx, a.ID, organization, "192.0.2.1", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	p := dbtest.Principal(a.ID, organization)
	p.SessionID = &pair.SessionID
	h := dbtest.Serve(p, (&Handler{Service: svc}).Mount)

	rec := dbtest.Do(t, h, http.MethodPost, "/mfa/push/step-up", nil)
	var started struct {
		ChallengeID uuid.UUID `json:"challenge_id"`
		Number      int       `json:"number"`
	}
	dbtest.Decode(t, rec, &started)
	if rec.Code != http.StatusAccepted || started.ChallengeID == uuid.Nil {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	complete := "/mfa/push/step-up/" + started.ChallengeID.String() + "/complete"
	if rec := dbtest.Do(t, h, http.MethodPost, complete, nil); rec.Code != http.StatusConflict {
		t.Errorf("complete before the phone answers: %d, want 409", rec.Code)
	}
	if err := svc.RespondToPushChallenge(ctx, started.ChallengeID, a.ID, device, true, started.Number); err != nil {
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
