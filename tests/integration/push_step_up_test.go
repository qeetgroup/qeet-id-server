//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
)

// TestALinkedPhoneIsAStepUpFactor: a linked phone is a second factor at
// sign-in, but step-up didn't count it and no route stepped up with it, so an
// account whose only factor is a phone was treated as having none — a stolen
// token could unlink the phone or pair another without a step-up — while the
// person could never complete an always-gated action. A phone now counts as a
// factor held, and a session steps up by approving a request on it, also where
// the organisation counts only push.
func TestALinkedPhoneIsAStepUpFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newStepUpMFA(t)
	authSvc, _ := newAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("phone-only"))
	person := createUserInTenant(t, ctx, tenantID)
	device, deviceToken, err := svc.RegisterPushDevice(ctx, person, "Phone", "ExponentPushToken["+uniqueSlug("tok")+"]", "ios")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := authSvc.IssuePair(ctx, person, tenantID, "203.0.113.70", "browser", "password")
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		r.Use(withSessionPrincipal(person, tenantID, pair.SessionID))
		r.Use(svc.StepUpGate(bootstrap.StepUpRoutes()))
		(&mfa.Handler{Service: svc}).Mount(r)
	})
	call := func(method, path string) (int, string) {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		return rr.Code, rr.Body.String()
	}
	stepUp := func(t *testing.T) {
		t.Helper()
		code, body := call(http.MethodPost, "/v1/mfa/push/step-up")
		if code != http.StatusAccepted {
			t.Fatalf("start a push step-up = %d %s, want 202", code, body)
		}
		var started struct {
			ChallengeID uuid.UUID `json:"challenge_id"`
		}
		_ = json.Unmarshal([]byte(body), &started)
		complete := "/v1/mfa/push/step-up/" + started.ChallengeID.String() + "/complete"
		if code, body := call(http.MethodPost, complete); code != http.StatusConflict || !strings.Contains(body, "mfa.push_pending") {
			t.Fatalf("complete before the phone answers = %d %s, want 409 mfa.push_pending", code, body)
		}
		if err := svc.RespondToPushChallenge(ctx, started.ChallengeID, person, deviceToken, true); err != nil {
			t.Fatalf("approve on the phone: %v", err)
		}
		if code, body := call(http.MethodPost, complete); code != http.StatusOK {
			t.Fatalf("complete after approval = %d %s, want 200", code, body)
		}
		if code, body := call(http.MethodPost, complete); code != http.StatusConflict || !strings.Contains(body, "mfa.push_challenge_invalid") {
			t.Fatalf("completing a spent request again = %d %s, want 409 mfa.push_challenge_invalid", code, body)
		}
	}

	for _, rt := range []struct{ method, path string }{
		{http.MethodPost, "/v1/mfa/push/pairing"},
		{http.MethodDelete, "/v1/mfa/push/devices/" + device.ID.String()},
	} {
		if code, body := call(rt.method, rt.path); code != http.StatusForbidden || !strings.Contains(body, "step_up_required") {
			t.Fatalf("%s %s from a phone-only account without a step-up = %d %s, want 403 step_up_required", rt.method, rt.path, code, body)
		}
	}
	stepUp(t)
	if code, body := call(http.MethodPost, "/v1/mfa/push/pairing"); code == http.StatusForbidden {
		t.Fatalf("pairing after a push step-up = %d %s, want it past the gate", code, body)
	}

	// An organisation that counts only push for step-up can be satisfied.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.security_policies (tenant_id, step_up_methods) VALUES ($1, ARRAY['push'])
		ON CONFLICT (tenant_id) DO UPDATE SET step_up_methods = EXCLUDED.step_up_methods`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM auth.mfa_verifications WHERE session_id = $1`, pair.SessionID); err != nil {
		t.Fatal(err)
	}
	if code, body := call(http.MethodPost, "/v1/mfa/push/pairing"); code != http.StatusForbidden {
		t.Fatalf("pairing without a step-up where only push counts = %d %s, want 403", code, body)
	}
	stepUp(t)
	if !stepUpMet(t, ctx, svc, person, pair.SessionID) {
		t.Fatal("a push step-up doesn't count where the organisation counts only push")
	}
}
