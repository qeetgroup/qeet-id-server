//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestEveryPasswordChangeEndsHostedSignIns: resetting or changing a password
// ended the person's console and API sessions but left every hosted sign-in
// session alive, which could still start an application's sign-in or — on an
// account with no second factor — enrol an attacker's passkey. A reset, a
// self-service change and an administrator's password set now end every hosted
// sign-in session of the person, and the audit record counts them; the
// self-service change keeps the session it was made from.
func TestEveryPasswordChangeEndsHostedSignIns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, users := newAuth()
	const oldPassword = "An-old-and-stolen-passphrase-1"

	// A hosted sign-in cookie reaching passkey enrolment, as the hosted login's
	// own page does.
	hosted := chi.NewRouter()
	hosted.Route("/v1", func(r chi.Router) {
		r.Use(authSvc.LoginSessionAuth(bootstrap.LoginSessionRoutes()))
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: mustIssuer()}))
		r.Post("/passkeys/register/begin", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})
	enrol := func(cookie string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/passkeys/register/begin", nil)
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		rr := httptest.NewRecorder()
		hosted.ServeHTTP(rr, req)
		return rr.Code
	}
	person := func(t *testing.T, tenantID uuid.UUID) (uuid.UUID, string) {
		t.Helper()
		email := uniqueSlug("person") + "@example.com"
		id := createTenantUser(t, ctx, tenantID, email)
		hash, err := password.Hash(oldPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`, id, hash); err != nil {
			t.Fatal(err)
		}
		return id, email
	}
	signedInHosted := func(t *testing.T, id uuid.UUID) string {
		t.Helper()
		cookie, err := authSvc.CreateLoginSession(ctx, id, "203.0.113.50", "attacker browser")
		if err != nil {
			t.Fatal(err)
		}
		if code := enrol(cookie); code != http.StatusOK {
			t.Fatalf("hosted session before the change reaches enrolment: %d", code)
		}
		return cookie
	}
	countedInAudit := func(t *testing.T, id uuid.UUID, action string) {
		t.Helper()
		var n string
		if err := testPool.QueryRow(ctx, `SELECT metadata->>'revoked_login_sessions' FROM audit.events
			WHERE resource_id = $1 AND action = $2 ORDER BY created_at DESC LIMIT 1`, id, action).Scan(&n); err != nil || n != "1" {
			t.Fatalf("%s revoked_login_sessions = %q (%v), want 1", action, n, err)
		}
	}

	t.Run("a password reset ends the hosted sign-in", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("reset"))
		id, email := person(t, tenantID)
		cookie := signedInHosted(t, id)
		rec := &recordSender{}
		svc := recovery.NewService(testPool, rec, time.Hour, "https://app.example")
		svc.SetPasswordRules(authpolicy.NewService(testPool))
		if _, err := svc.StartPasswordReset(ctx, email); err != nil {
			t.Fatal(err)
		}
		if err := svc.ConfirmPasswordReset(ctx, extractToken(t, rec.last.Body), "A-new-passphrase-the-owner-chose-2", recovery.AuditCtx{}); err != nil {
			t.Fatal(err)
		}
		if code := enrol(cookie); code != http.StatusUnauthorized {
			t.Fatalf("hosted session after the reset begins passkey enrolment: %d, want 401", code)
		}
		countedInAudit(t, id, "auth.password_reset_confirmed")
	})

	t.Run("a self-service change ends hosted sign-ins and keeps its own session", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("change"))
		id, _ := person(t, tenantID)
		cookie := signedInHosted(t, id)
		own, err := authSvc.IssuePair(ctx, id, tenantID, "198.51.100.5", "owner browser", "password")
		if err != nil {
			t.Fatal(err)
		}
		if err := authSvc.ChangePassword(ctx, auth.ChangePasswordInput{UserID: id, KeepSessionID: own.SessionID, TenantID: &tenantID,
			Current: oldPassword, Next: "A-new-passphrase-the-owner-chose-3"}); err != nil {
			t.Fatal(err)
		}
		if code := enrol(cookie); code != http.StatusUnauthorized {
			t.Fatalf("hosted session after the change begins passkey enrolment: %d, want 401", code)
		}
		var kept bool
		if err := testPool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM auth.sessions WHERE id = $1`, own.SessionID).Scan(&kept); err != nil || !kept {
			t.Fatalf("the calling session ended too (kept=%v, %v)", kept, err)
		}
		countedInAudit(t, id, "auth.password_changed")
	})

	t.Run("an administrator setting the password ends the member's hosted sign-ins", func(t *testing.T) {
		tenantID := createTenant(t, ctx, uniqueSlug("admin-set"))
		id, _ := person(t, tenantID)
		cookie := signedInHosted(t, id)
		admin := uuid.New()
		h := &user.Handler{Repo: users, Validate: validator.New(), SignIns: authSvc,
			PasswordPolicy: authpolicy.NewService(testPool).ValidateForTenant}
		router := chi.NewRouter()
		router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &admin, TenantID: &tenantID})))
			})
		})
		router.Route("/v1", h.Mount)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/users/"+id.String()+"/password",
			bytes.NewBufferString(`{"password":"An-admin-set-passphrase-4"}`)))
		if rr.Code >= 300 {
			t.Fatalf("set password = %d %s", rr.Code, rr.Body.String())
		}
		if code := enrol(cookie); code != http.StatusUnauthorized {
			t.Fatalf("hosted session after the administrator's set begins passkey enrolment: %d, want 401", code)
		}
		countedInAudit(t, id, "user.password_set")
	})
}
