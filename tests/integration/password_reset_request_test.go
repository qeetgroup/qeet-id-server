//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
)

// postForgotPassword sends a forgot-password request through the real handler
// and returns the HTTP status.
func postForgotPassword(t *testing.T, svc *recovery.Service, body string) int {
	t.Helper()
	r := chi.NewRouter()
	(&recovery.Handler{Service: svc}).Mount(r)
	req := httptest.NewRequest(http.MethodPost, "/auth/forgot-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// TestForgotPasswordAcceptsCallerFields: hosted login and the React SDK send
// tenant_id with a forgot-password request, and hosted login says where the
// reset came from (app, return_to). None of these may turn the request into an
// error — the user must get the email.
func TestForgotPasswordAcceptsCallerFields(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("fpw"))

	for _, tc := range []struct{ name, extra string }{
		{"with tenant_id (hosted login, React SDK)", `,"tenant_id":"` + tid.String() + `"`},
		{"with app and return_to (hosted login)", `,"app":"hosted_login","return_to":"http://example.com/v1/oauth/authorize?client_id=c1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueSlug("fpw") + "@example.com"
			createTenantUser(t, ctx, tid, email)
			sender := &captureSender{}
			code := postForgotPassword(t, newRecovery(sender), `{"email":"`+email+`"`+tc.extra+`}`)
			if code != http.StatusOK {
				t.Fatalf("forgot-password returned %d, want 200", code)
			}
			if sender.count() != 1 {
				t.Fatalf("want exactly 1 reset email, got %d", sender.count())
			}
		})
	}
}

// TestPasswordResetLinkTarget: the emailed link lands in the application the
// reset was requested from. Hosted login gets its own reset page,
// carrying the return_to only when it is this service's authorize endpoint;
// the console — and any request that does not say — keeps the console link.
func TestPasswordResetLinkTarget(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("rlink"))
	// httptest requests are addressed to example.com, standing in for the API.
	authorize := "http://example.com/v1/oauth/authorize?client_id=c1&state=s"

	for _, tc := range []struct{ name, extra, wantPrefix string }{
		{"console (no app given)", ``, "http://app.test/forgot-password?token="},
		{"unknown app falls back to the console", `,"app":"mobile"`, "http://app.test/forgot-password?token="},
		{"hosted login", `,"app":"hosted_login"`, "http://login.test/reset?token="},
		{"hosted login with its authorize return_to", `,"app":"hosted_login","return_to":"` + authorize + `"`,
			"http://login.test/reset?return_to=" + url.QueryEscape(authorize) + "&token="},
		{"return_to on another site is dropped", `,"app":"hosted_login","return_to":"https://evil.example/v1/oauth/authorize?client_id=c1"`,
			"http://login.test/reset?token="},
		{"return_to that is not the authorize endpoint is dropped", `,"app":"hosted_login","return_to":"http://example.com/v1/admin"`,
			"http://login.test/reset?token="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueSlug("rlink") + "@example.com"
			createTenantUser(t, ctx, tid, email)
			sender := &captureSender{}
			svc := newRecovery(sender)
			svc.SetHostedLogin("http://login.test")
			if code := postForgotPassword(t, svc, `{"email":"`+email+`"`+tc.extra+`}`); code != http.StatusOK {
				t.Fatalf("forgot-password returned %d, want 200", code)
			}
			msg, ok := sender.last()
			if !ok {
				t.Fatal("no reset email sent")
			}
			link := msg.Body[strings.Index(msg.Body, "http"):]
			if !strings.HasPrefix(link, tc.wantPrefix) {
				t.Fatalf("reset link = %q, want it to start with %q", link, tc.wantPrefix)
			}
			// The link's token completes the reset, wherever the link lands.
			if err := svc.ConfirmPasswordReset(ctx, tokenFromBody(t, link), "Correct-Horse-Battery-9", recovery.AuditCtx{}); err != nil {
				t.Fatalf("reset with the emailed token: %v", err)
			}
		})
	}
}
