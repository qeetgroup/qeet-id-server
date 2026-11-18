package mfa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
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
