package mfa

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMaskDestination(t *testing.T) {
	cases := []struct {
		name    string
		channel string
		dest    string
		want    string
	}{
		// Email: keep first char + domain, star out the local part's tail.
		{"email typical", "email", "alice@example.com", "a****@example.com"},
		{"email short local", "email", "ab@x.io", "a*@x.io"},
		// at <= 1: a single-char local part (or leading '@') is returned as-is,
		// since masking it would reveal nothing useful and risk index issues.
		{"email single-char local", "email", "a@x.io", "a@x.io"},
		{"email leading at", "email", "@nolocal.io", "@nolocal.io"},
		// Phone: keep the last three digits.
		{"phone typical", "sms", "+15555550123", "*********123"},
		{"phone short", "sms", "12", "12"},
		{"phone exactly three", "sms", "123", "123"},
		{"phone four", "sms", "1234", "*234"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := maskDestination(c.channel, c.dest); got != c.want {
				t.Errorf("maskDestination(%q, %q) = %q, want %q", c.channel, c.dest, got, c.want)
			}
		})
	}
}

func TestMaskDestination_EmailHidesLocalLength(t *testing.T) {
	// The star count equals (at-1); the masked output's local part length must
	// match the original so the UI hint stays stable, but the chars are hidden.
	masked := maskDestination("email", "verylongname@corp.example")
	if !strings.HasPrefix(masked, "v") || !strings.HasSuffix(masked, "@corp.example") {
		t.Fatalf("unexpected mask: %q", masked)
	}
	stars := strings.Count(masked, "*")
	if stars != len("verylongname")-1 {
		t.Errorf("masked %d chars, want %d", stars, len("verylongname")-1)
	}
}

// TestRecoveryCodeCount checks that a batch holds 10 recovery codes.
func TestRecoveryCodeCount(t *testing.T) {
	if recoveryCodeCount != 10 {
		t.Errorf("recoveryCodeCount = %d, want 10", recoveryCodeCount)
	}
}

// TestDefaultStepUpWindow checks that the step-up window used when no
// organisation is known is 5 minutes, the migration's column default.
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

// TestTOTPStatusUnauthenticated checks that the TOTP status endpoint refuses
// an anonymous caller with 401, before touching the database.
func TestTOTPStatusUnauthenticated(t *testing.T) {
	h := &Handler{Service: &Service{}}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/mfa/totp", nil)
	h.totpStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

// TestRecoveryCodeHashing checks that recovery codes are stored as salted
// one-way hashes: the right code verifies, a wrong one doesn't, and equal
// codes hash differently.
func TestRecoveryCodeHashing(t *testing.T) {
	const code = "0123456789"
	h1, err := password.Hash(code)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h1 == code {
		t.Fatal("recovery code must not be stored in plaintext")
	}
	if !password.Verify(h1, code) {
		t.Error("the correct recovery code must verify against its hash")
	}
	if password.Verify(h1, "9999999999") {
		t.Error("a wrong recovery code must not verify")
	}
	h2, _ := password.Hash(code)
	if h1 == h2 {
		t.Error("identical recovery codes must hash to distinct (salted) values")
	}
	// Each independently-salted hash still verifies its own plaintext.
	if !password.Verify(h2, code) {
		t.Error("second salted hash must still verify the same code")
	}
}
