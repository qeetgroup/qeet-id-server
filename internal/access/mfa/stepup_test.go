package mfa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestDefaultStepUpWindow checks that the step-up window used when no
// organization is known is 5 minutes, the migration's column default.
func TestDefaultStepUpWindow(t *testing.T) {
	if defaultStepUpWindow != 5*time.Minute {
		t.Errorf("defaultStepUpWindow = %v, want 5m", defaultStepUpWindow)
	}
}

// TestStepUpRequiredError checks that the gate's error carries the stable
// step_up_required code clients branch on.
func TestStepUpRequiredError(t *testing.T) {
	if errs.ErrStepUpRequired.Code != errs.CodeStepUpRequired {
		t.Errorf("code = %q, want step_up_required", errs.ErrStepUpRequired.Code)
	}
}

// TestRequireRecentMFAUnauthenticated checks that the gate refuses a request
// with no principal with 401, before touching the database.
func TestRequireRecentMFAUnauthenticated(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	// No DB access on this path — the step-up is never read.
	h := RequireRecentMFA(&Service{})(next)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/mfa/totp", nil)
	h.ServeHTTP(rr, req)

	if called {
		t.Fatal("next handler must not run without an authenticated principal")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestRequireRecentMFAWithoutSession checks that a principal with no session
// (such as an API key) never passes the gate: a step-up belongs to a session.
func TestRequireRecentMFAWithoutSession(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	h := RequireRecentMFA(&Service{})(next)

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
