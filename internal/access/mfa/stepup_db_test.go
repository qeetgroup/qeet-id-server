//go:build integration

package mfa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestStepUpGate checks that a route always needing a step-up refuses a
// session until it meets a second factor, that one needing it while a factor
// is held asks it only of someone holding one and a recent sign-in of anyone
// else, and that a step-up belongs to its session alone.
func TestStepUpGate(t *testing.T) {
	ctx := dbtest.Context(t)
	mfaSvc, authSvc := services(t, notifier.LogSender{})
	a, organization := member(t)
	signIn := func() *auth.TokenPair {
		t.Helper()
		pair, err := authSvc.IssuePair(ctx, a.ID, organization, "192.0.2.1", "test", "password")
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		return pair
	}
	gate := mfaSvc.StepUpGate(map[string]StepUpRule{"POST /always": StepUpAlways, "POST /when-held": StepUpOrRecentSignIn})
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	serve := func(session uuid.UUID) http.Handler {
		p := dbtest.Principal(a.ID, organization)
		p.SessionID = &session
		return dbtest.Serve(p, func(r chi.Router) {
			r.Use(gate)
			r.Post("/always", ok)
			r.Post("/when-held", ok)
			r.Post("/open", ok)
		})
	}
	expect := func(h http.Handler, path string, want int) {
		t.Helper()
		if rec := dbtest.Do(t, h, http.MethodPost, path, nil); rec.Code != want {
			t.Errorf("POST %s: %d %s; want %d", path, rec.Code, rec.Body.String(), want)
		}
	}

	session := signIn().SessionID
	h := serve(session)
	expect(h, "/open", http.StatusOK)
	expect(h, "/always", http.StatusForbidden)
	expect(h, "/when-held", http.StatusOK)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.sessions SET signed_in_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, session); err != nil {
		t.Fatal(err)
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/when-held", nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeRecentSignIn) {
		t.Errorf("a sign-in an hour old with no factor: %d %s, want 403 %s", rec.Code, rec.Body.String(), CodeRecentSignIn)
	}
	expect(serve(signIn().SessionID), "/when-held", http.StatusOK)

	enrolTOTP(t, mfaSvc, a)
	expect(h, "/when-held", http.StatusForbidden)
	if err := inTx(t, func(tx pgx.Tx) error { return mfaSvc.RecordVerification(ctx, tx, a.ID, session, "totp") }); err != nil {
		t.Fatalf("record step-up: %v", err)
	}
	expect(h, "/always", http.StatusOK)
	expect(h, "/when-held", http.StatusOK)
	expect(serve(signIn().SessionID), "/always", http.StatusForbidden)
}

// TestRequireRecentMFAWithoutSession checks that a principal with no session
// (such as an API key) never passes the gate: a step-up belongs to a session.
func TestRequireRecentMFAWithoutSession(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	svc, _ := services(t, notifier.LogSender{})
	h := RequireRecentMFA(svc)(next)

	uid := uuid.New()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/mfa/totp", nil)
	req = req.WithContext(httpx.WithPrincipal(req.Context(), &httpx.Principal{UserID: &uid, ActorType: "api_key"}))
	h.ServeHTTP(rr, req)

	if called {
		t.Fatal("a principal without a session must not pass the step-up gate")
	}
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "step_up_required") {
		t.Errorf("got %d %q, want 403 step_up_required", rr.Code, rr.Body.String())
	}
}
