//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	authhook "github.com/qeetgroup/qeet-id-server/internal/developer/auth-hooks"
	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	webhook "github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	group "github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/siem"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// mustIssuer builds an ES256 token issuer over a freshly-generated key for the
// integration flows (each call mints its own key, which is fine in-process).
func mustIssuer() *tokens.Issuer {
	keyPEM, err := tokens.GenerateES256KeyPEM()
	if err != nil {
		panic("generate signing key: " + err.Error())
	}
	i, err := tokens.NewIssuer(keyPEM, "qeet", "qeet", 15*time.Minute, 720*time.Hour)
	if err != nil {
		panic("new issuer: " + err.Error())
	}
	return i
}

func newAuth() (*auth.Service, *user.Repository) {
	users := user.NewRepository(testPool)
	issuer := mustIssuer()
	svc := auth.NewService(testPool, users, issuer)
	policy := authpolicy.NewService(testPool)
	svc.SetRegistrationPolicy(policy) // the password check, as bootstrap wires it
	svc.SetMethodPolicy(policy)       // which sign-in methods an organisation allows
	return svc, users
}

func TestOrganizationSelectionEligibility(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	repository := tenant.NewRepository(testPool)
	svc, _ := newAuth()
	home := createTenant(t, ctx, uniqueSlug("selection"))
	userID := createUserInTenant(t, ctx, home)
	eligible := []uuid.UUID{home}
	for range 4 {
		eligible = append(eligible, createTenant(t, ctx, uniqueSlug("selection")))
	}
	for _, organization := range eligible {
		addTenantMembership(t, ctx, userID, organization)
	}
	foreign := createTenant(t, ctx, uniqueSlug("foreign-selection"))
	suspended := createTenant(t, ctx, uniqueSlug("suspended-selection"))
	deleted := createTenant(t, ctx, uniqueSlug("deleted-selection"))
	for _, organization := range []uuid.UUID{suspended, deleted} {
		addTenantMembership(t, ctx, userID, organization)
	}
	if _, err := testPool.Exec(ctx, `UPDATE tenant.tenants SET status='suspended' WHERE id=$1`, suspended); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE tenant.tenants SET deleted_at=NOW(), status='deleted' WHERE id=$1`, deleted); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO tenant.domains (tenant_id,domain,verification_token,verified_at) VALUES ($1,$2,$3,NOW())`, home, uniqueSlug("selection")+".example.test", uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	current, err := svc.IssuePair(ctx, userID, home, "", "", "password")
	if err != nil {
		t.Fatal(err)
	}
	page, err := repository.EligibleOrganizations(ctx, userID, current.SessionID, 2, "")
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page: %+v, %v", page, err)
	}
	next, err := repository.EligibleOrganizations(ctx, userID, current.SessionID, 200, page.NextCursor)
	if err != nil || len(next.Items) != 3 || next.NextCursor != "" {
		t.Fatalf("next page: %+v, %v", next, err)
	}
	for _, organization := range append(page.Items, next.Items...) {
		if !slices.Contains(eligible, organization.ID) || len(organization.Roles) == 0 {
			t.Fatalf("unexpected membership: %+v", organization)
		}
		if organization.LastUsedAt != nil {
			t.Fatal("current sign-in must not count as last used")
		}
		if organization.ID == home && organization.Domain == "" {
			t.Fatal("verified domain omitted")
		}
	}
	previous, err := svc.IssuePair(ctx, userID, eligible[1], "", "", "tenant_switch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.sessions SET last_seen_at=NOW()-interval '1 day' WHERE id=$1`, previous.SessionID); err != nil {
		t.Fatal(err)
	}
	page, err = repository.EligibleOrganizations(ctx, userID, current.SessionID, 200, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, organization := range page.Items {
		if organization.ID == eligible[1] && organization.LastUsedAt == nil {
			t.Fatal("prior use omitted")
		}
	}
	for _, denied := range []uuid.UUID{foreign, suspended, deleted} {
		if _, err := svc.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: userID, FromSessionID: current.SessionID, TenantID: denied}); !errors.Is(err, errs.ErrAuthNotTenantMember) {
			t.Fatalf("ineligible switch allowed: %v", err)
		}
	}
	switched, err := svc.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: userID, FromSessionID: current.SessionID, TenantID: eligible[2]})
	if err != nil {
		t.Fatalf("eligible switch rejected: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id=$1 AND tenant_id=$2`, userID, eligible[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: userID, FromSessionID: switched.SessionID, TenantID: eligible[2]}); !errors.Is(err, errs.ErrAuthNotTenantMember) {
		t.Fatal("removed membership remained switchable")
	}
	if _, err := repository.EligibleOrganizations(ctx, userID, current.SessionID, 200, "invalid"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	router := chi.NewRouter()
	router.Use(withPrincipal(userID, home))
	(&tenant.Handler{Repo: repository}).Mount(router)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "/me/organizations?user_id="+uuid.NewString(), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("self list status: %d %s", response.Code, response.Body.String())
	}
	var result tenant.OrganizationSelectionPage
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 4 {
		t.Fatalf("self list not caller-scoped: %d", len(result.Items))
	}
}

type fixedSAMLSession struct{ userID uuid.UUID }

func (s fixedSAMLSession) ResolveLoginSession(context.Context, string) (uuid.UUID, error) {
	return s.userID, nil
}

// Signup is tenant-less, login works, refresh rotates, and reusing a rotated
// refresh token is treated as theft (revokes the session).
func TestAuthSignupLoginRefreshReuse(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	email := uniqueSlug("user") + "@example.com"

	pair, u, brief, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if u.TenantID != uuid.Nil || brief != nil || pair.TenantID != nil {
		t.Fatalf("signup should be tenant-less: tenantID=%v brief=%v pair.TenantID=%v", u.TenantID, brief, pair.TenantID)
	}

	lp, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	rotated, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: lp.Pair.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == lp.Pair.RefreshToken {
		t.Fatal("refresh should rotate the token")
	}

	// Reusing the now-consumed token must fail (theft detection).
	if _, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: lp.Pair.RefreshToken}); err == nil {
		t.Fatal("reusing a consumed refresh token should fail")
	}
	// ...and that revokes the session, so the freshly-rotated token is dead too.
	if _, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: rotated.RefreshToken}); err == nil {
		t.Fatal("session should be revoked after reuse, rotated token must fail")
	}
}

// Login gates on a second factor once TOTP is enrolled: a plain password login
// returns an mfa_required challenge, and only a valid code (via CompleteMFALogin)
// yields tokens. The challenge is single-use.
func TestLoginMFAEnforcement(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	svc := auth.NewService(testPool, users, mustIssuer())
	svc.SetRegistrationPolicy(authpolicy.NewService(testPool))
	mfaSvc := mfa.NewService(testPool, "qeet", notifier.LogSender{}, "")
	mfaSvc.SetCipher(testEnvelope(t))
	svc.SetMFA(mfaSvc)

	email := uniqueSlug("mfa") + "@example.com"
	if _, _, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM "user".users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("lookup user: %v", err)
	}

	// Before enrollment: login issues tokens directly.
	res, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.MFARequired || res.Pair == nil {
		t.Fatalf("pre-enroll login should issue tokens, got MFARequired=%v pair=%v", res.MFARequired, res.Pair)
	}

	// Enroll + confirm TOTP.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	enr, err := mfaSvc.StartEnroll(ctx, tx, userID, email)
	if err != nil {
		t.Fatalf("totp start: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	code, err := totp.Code(enr.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if _, err := mfaConfirmEnroll(ctx, mfaSvc, userID, code); err != nil {
		t.Fatalf("totp confirm: %v", err)
	}

	// Now login must challenge for a second factor — no tokens yet.
	res, err = svc.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("login after enroll: %v", err)
	}
	if !res.MFARequired || res.MFAToken == "" || res.Pair != nil {
		t.Fatalf("post-enroll login should require MFA, got %+v", res)
	}

	// Wrong code is rejected; the challenge survives for a retry.
	if _, err := svc.CompleteMFALogin(ctx, res.MFAToken, "000000", "", ""); err == nil {
		t.Fatal("wrong mfa code should fail")
	}

	// Correct code completes the login. Step +1: the enrollment confirm above
	// consumed the current step, and a consumed step is rejected as a replay.
	good := totpCodeAtStep(t, enr.Secret, 1)
	pair, err := svc.CompleteMFALogin(ctx, res.MFAToken, good, "", "")
	if err != nil {
		t.Fatalf("complete mfa: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatalf("expected a token pair, got %+v", pair)
	}

	// The challenge is single-use — replaying it fails.
	if _, err := svc.CompleteMFALogin(ctx, res.MFAToken, good, "", ""); err == nil {
		t.Fatal("consumed mfa challenge should not be reusable")
	}
}

func TestMFALoginAttemptBudgetAndConcurrentConsumption(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	authService := auth.NewService(testPool, users, mustIssuer())
	authService.SetRegistrationPolicy(authpolicy.NewService(testPool))
	mfaService := mfa.NewService(testPool, "qeet", notifier.LogSender{}, "")
	mfaService.SetCipher(testEnvelope(t))
	authService.SetMFA(mfaService)
	email := uniqueSlug("mfa-login-budget") + "@example.com"
	if _, _, _, err := authService.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM "user".users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("lookup user: %v", err)
	}
	tx, _ := testPool.Begin(ctx)
	enrollment, err := mfaService.StartEnroll(ctx, tx, userID, email)
	if err != nil {
		t.Fatalf("start enrollment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enrollment: %v", err)
	}
	// This test authenticates three separate times with one secret. A consumed
	// TOTP step is now rejected as a replay, and verification only accepts
	// now-1/now/now+1 — so the three uses must walk the window in ascending
	// order: -1 here, 0 after lockout expiry, +1 for the concurrency race.
	code := totpCodeAtStep(t, enrollment.Secret, -1)
	if _, err := mfaConfirmEnroll(ctx, mfaService, userID, code); err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}

	login, err := authService.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil || !login.MFARequired {
		t.Fatalf("start MFA login: result=%+v err=%v", login, err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		_, verifyErr := authService.CompleteMFALogin(ctx, login.MFAToken, "not-a-code", fmt.Sprintf("198.51.100.%d", attempt), "test")
		if attempt < 5 && !errors.Is(verifyErr, errs.ErrMFACodeInvalid) {
			t.Fatalf("login attempt %d error = %v", attempt, verifyErr)
		}
		if attempt == 5 && !errors.Is(verifyErr, errs.ErrMFAAttemptsExceeded) {
			t.Fatalf("fifth login attempt error = %v, want exhausted", verifyErr)
		}
	}
	if _, err := authService.CompleteMFALogin(ctx, login.MFAToken, code, "203.0.113.1", "test"); err == nil {
		t.Fatal("correct code must not revive an exhausted challenge")
	}
	lockedLogin, err := authService.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil || !lockedLogin.MFARequired {
		t.Fatalf("start second MFA login: result=%+v err=%v", lockedLogin, err)
	}
	if _, err := authService.CompleteMFALogin(ctx, lockedLogin.MFAToken, code, "203.0.113.2", "test"); !errors.Is(err, errs.ErrMFAAttemptsExceeded) {
		t.Fatalf("correct code during account lockout error = %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET locked_until = NOW() - INTERVAL '1 second', window_started_at = NOW() - INTERVAL '11 minutes'
		WHERE user_id = $1 AND purpose = 'login'
	`, userID); err != nil {
		t.Fatalf("expire login MFA budget: %v", err)
	}
	// Step +1 — enrollment consumed the current step, and a consumed step is
	// rejected as a replay.
	code = totpCodeAtStep(t, enrollment.Secret, 0)
	if _, err := authService.CompleteMFALogin(ctx, lockedLogin.MFAToken, code, "203.0.113.3", "test"); err != nil {
		t.Fatalf("complete login after lockout expiry: %v", err)
	}

	if _, err := testPool.Exec(ctx, `DELETE FROM auth.sessions WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("clear sessions before race: %v", err)
	}
	raceLogin, err := authService.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil || !raceLogin.MFARequired {
		t.Fatalf("start raced MFA login: result=%+v err=%v", raceLogin, err)
	}
	// Step +1 — the last unconsumed step in the acceptance window. Exactly one
	// contender may win; both the single-use MFA challenge and the single-use
	// TOTP step independently guarantee that.
	code = totpCodeAtStep(t, enrollment.Secret, 1)
	const contenders = 12
	start := make(chan struct{})
	results := make(chan bool, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			pair, err := authService.CompleteMFALogin(ctx, raceLogin.MFAToken, code, "198.51.100.20", "race")
			results <- err == nil && pair != nil
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for success := range results {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent MFA challenge successes = %d, want 1", successes)
	}
	var sessions int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, userID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions after race: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("concurrent MFA challenge created %d sessions, want 1", sessions)
	}
}

func TestChangePasswordIsAtomicWithSessionRevocationAndEvidence(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	service := auth.NewService(testPool, users, mustIssuer())
	service.SetRegistrationPolicy(authpolicy.NewService(testPool))

	createAccount := func(prefix string) (*auth.TokenPair, *user.User) {
		t.Helper()
		pair, account, _, err := service.Signup(ctx, auth.SignupInput{
			Email: uniqueSlug(prefix) + "@example.com", Password: "Kx7mQ2vLp9Wz",
		})
		if err != nil {
			t.Fatalf("signup %s: %v", prefix, err)
		}
		if _, err := service.IssuePair(ctx, account.ID, uuid.Nil, "198.51.100.2", "second-session", "password"); err != nil {
			t.Fatalf("create second session: %v", err)
		}
		return pair, account
	}

	current, account := createAccount("password-atomic-ok")
	if err := service.ChangePassword(ctx, auth.ChangePasswordInput{
		UserID: account.ID, KeepSessionID: current.SessionID,
		Current: "Kx7mQ2vLp9Wz", Next: "Nz8pR3wMq7Yv", RequestID: "password-success",
	}); err != nil {
		t.Fatalf("change password: %v", err)
	}
	var currentRevoked bool
	var activeSessions int
	if err := testPool.QueryRow(ctx, `
		SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE id = $1
	`, current.SessionID).Scan(&currentRevoked); err != nil {
		t.Fatalf("inspect current session: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL
	`, account.ID).Scan(&activeSessions); err != nil {
		t.Fatalf("count active sessions: %v", err)
	}
	if currentRevoked || activeSessions != 1 {
		t.Fatalf("password change session state current_revoked=%v active=%d", currentRevoked, activeSessions)
	}
	var auditCount, outboxCount int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.password_changed'`, account.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count password audit: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'auth.password.changed'`, account.ID).Scan(&outboxCount); err != nil {
		t.Fatalf("count password outbox: %v", err)
	}
	if auditCount != 1 || outboxCount != 1 {
		t.Fatalf("password evidence audit=%d outbox=%d, want 1 each", auditCount, outboxCount)
	}

	failingCurrent, failingAccount := createAccount("password-atomic-fail")
	suffix := strings.ReplaceAll(failingAccount.ID.String(), "-", "")
	functionName := "test_fail_session_revoke_" + suffix
	triggerName := "test_fail_session_revoke_" + suffix
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced session revocation failure';
		END $$;
		CREATE TRIGGER %s BEFORE UPDATE ON auth.sessions
		FOR EACH ROW WHEN (OLD.user_id = '%s'::uuid) EXECUTE FUNCTION %s();
	`, functionName, triggerName, failingAccount.ID, functionName)); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON auth.sessions", triggerName))
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
	})
	changeErr := service.ChangePassword(ctx, auth.ChangePasswordInput{
		UserID: failingAccount.ID, KeepSessionID: failingCurrent.SessionID,
		Current: "Kx7mQ2vLp9Wz", Next: "Qp9vL4mNz8Rx", RequestID: "password-failure",
	})
	if changeErr == nil {
		t.Fatal("forced session revocation failure should fail password change")
	}
	if _, err := service.Login(ctx, auth.LoginInput{Email: failingAccount.Email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("old password must remain valid after rollback: %v", err)
	}
	if _, err := service.Login(ctx, auth.LoginInput{Email: failingAccount.Email, Password: "Qp9vL4mNz8Rx"}); err == nil {
		t.Fatal("new password must not become valid after rollback")
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.password_changed'`, failingAccount.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count rolled-back audit: %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'auth.password.changed'`, failingAccount.ID).Scan(&outboxCount); err != nil {
		t.Fatalf("count rolled-back outbox: %v", err)
	}
	if auditCount != 0 || outboxCount != 0 {
		t.Fatalf("failed password change left evidence rows audit=%d outbox=%d", auditCount, outboxCount)
	}
}

func TestSessionPaginationBeyondOneHundredAndCursorOwnership(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("session-page"))
	userID := createUserInTenant(t, ctx, tenantID)
	otherUserID := createUserInTenant(t, ctx, tenantID)
	service := auth.NewService(testPool, user.NewRepository(testPool), mustIssuer())
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.sessions (user_id, tenant_id, created_at, last_seen_at, user_agent)
		SELECT $1, $2, NOW() - (series || ' seconds')::interval,
		       NOW() - (series || ' seconds')::interval, 'page-test'
		FROM generate_series(1, 205) AS series
	`, userID, tenantID); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}
	var otherCursor uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2) RETURNING id
	`, otherUserID, tenantID).Scan(&otherCursor); err != nil {
		t.Fatalf("seed foreign cursor: %v", err)
	}

	seen := map[uuid.UUID]bool{}
	cursor := ""
	pages := 0
	var oldSession uuid.UUID
	for {
		page, err := service.ListSessionsPage(ctx, userID, 75, cursor)
		if err != nil {
			t.Fatalf("list session page %d: %v", pages+1, err)
		}
		pages++
		if page.Total != 205 {
			t.Fatalf("page total = %d, want 205", page.Total)
		}
		for _, session := range page.Items {
			if seen[session.ID] {
				t.Fatalf("session %s appeared on multiple pages", session.ID)
			}
			seen[session.ID] = true
			oldSession = session.ID
		}
		if !page.HasMore {
			if page.NextCursor != "" {
				t.Fatalf("final page has unexpected cursor %q", page.NextCursor)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatal("non-final session page has no next cursor")
		}
		cursor = page.NextCursor
	}
	if len(seen) != 205 || pages != 3 {
		t.Fatalf("session pagination saw %d sessions across %d pages, want 205 across 3", len(seen), pages)
	}
	if err := service.Logout(ctx, oldSession, userID); err != nil {
		t.Fatalf("revoke older paged session: %v", err)
	}
	var revoked bool
	if err := testPool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE id = $1`, oldSession).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("older paged session revoked=%v err=%v", revoked, err)
	}
	if _, err := service.ListSessionsPage(ctx, userID, 50, otherCursor.String()); !errors.Is(err, errs.ErrBadRequest) {
		t.Fatalf("foreign cursor error = %v, want bad request", err)
	}
	if _, err := service.ListSessionsPage(ctx, userID, 50, "tampered-cursor"); !errors.Is(err, errs.ErrBadRequest) {
		t.Fatalf("tampered cursor error = %v, want bad request", err)
	}
}

func TestUserCreationRollsBackWhenOutboxFails(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("user-create-atomic"))
	actorID := createUserInTenant(t, ctx, tenantID)
	repository := user.NewRepository(testPool)
	handler := &user.Handler{Repo: repository, Validate: validator.New()}
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(withPrincipal(actorID, tenantID))
	handler.Mount(router)

	functionName := "test_fail_user_outbox_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	triggerName := functionName
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type = 'user.created' THEN
				RAISE EXCEPTION 'forced user outbox failure';
			END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER %s BEFORE INSERT ON platform.outbox
		FOR EACH ROW EXECUTE FUNCTION %s();
	`, functionName, triggerName, functionName)); err != nil {
		t.Fatalf("install outbox failure trigger: %v", err)
	}
	dropTrigger := func() {
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON platform.outbox", triggerName))
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
	}
	t.Cleanup(dropTrigger)

	failedEmail := uniqueSlug("atomic-fail") + "@example.com"
	body, _ := json.Marshal(map[string]any{"email": failedEmail, "display_name": "Atomic Failure"})
	request := httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("forced-outbox create status = %d, want 500: %s", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM "user".users WHERE email = $1`, failedEmail).Scan(&count); err != nil {
		t.Fatalf("count rolled-back user: %v", err)
	}
	if count != 0 {
		t.Fatalf("forced outbox failure left %d user rows", count)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE metadata->>'email' = $1`, failedEmail).Scan(&count); err != nil {
		t.Fatalf("count rolled-back user audit: %v", err)
	}
	if count != 0 {
		t.Fatalf("forced outbox failure left %d audit rows", count)
	}
	dropTrigger()

	successEmail := uniqueSlug("atomic-success") + "@example.com"
	body, _ = json.Marshal(map[string]any{"email": successEmail, "display_name": "Atomic Success"})
	request = httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("successful create status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var createdID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM "user".users WHERE email = $1`, successEmail).Scan(&createdID); err != nil {
		t.Fatalf("load created user: %v", err)
	}
	var auditActor uuid.UUID
	var requestID string
	if err := testPool.QueryRow(ctx, `
		SELECT actor_user_id, request_id FROM audit.events
		WHERE resource_id = $1 AND action = 'user.created'
	`, createdID).Scan(&auditActor, &requestID); err != nil {
		t.Fatalf("load user audit evidence: %v", err)
	}
	if auditActor != actorID || requestID == "" {
		t.Fatalf("user audit provenance actor=%s request_id=%q", auditActor, requestID)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM platform.outbox WHERE aggregate_id = $1 AND event_type = 'user.created'`, createdID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("user outbox rows = %d (err %v), want 1", count, err)
	}
}

// Admin MFA reset clears a user's enrolled factors so a locked-out user can
// re-enroll (the service method behind DELETE /v1/users/{id}/mfa).
func TestAdminResetMFA(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	svc := auth.NewService(testPool, users, mustIssuer())
	svc.SetRegistrationPolicy(authpolicy.NewService(testPool))
	mfaSvc := mfa.NewService(testPool, "qeet", notifier.LogSender{}, "")
	mfaSvc.SetCipher(testEnvelope(t))

	email := uniqueSlug("reset") + "@example.com"
	if _, _, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM "user".users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("lookup: %v", err)
	}

	// Enroll + confirm TOTP.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	enr, err := mfaSvc.StartEnroll(ctx, tx, userID, email)
	if err != nil {
		t.Fatalf("totp start: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	code, err := totp.Code(enr.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if _, err := mfaConfirmEnroll(ctx, mfaSvc, userID, code); err != nil {
		t.Fatalf("totp confirm: %v", err)
	}
	if ok, err := mfaSvc.IsEnrolled(ctx, userID); err != nil || !ok {
		t.Fatalf("expected enrolled before reset (ok=%v err=%v)", ok, err)
	}

	// Admin reset wipes the factors.
	rtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	if _, err := mfaSvc.ResetForUser(ctx, rtx, userID); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := rtx.Commit(ctx); err != nil {
		t.Fatalf("commit reset: %v", err)
	}
	if ok, err := mfaSvc.IsEnrolled(ctx, userID); err != nil || ok {
		t.Fatalf("expected NOT enrolled after reset (ok=%v err=%v)", ok, err)
	}
}

// Hosted-login SSO session: credentials create a session, it resolves to the
// user, and revoking (hosted logout) invalidates it.
func TestHostedLoginSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	email := uniqueSlug("sso") + "@example.com"

	if _, u, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	} else if u.ID == uuid.Nil {
		t.Fatal("signup returned nil user id")
	}

	// Wrong password is rejected by the shared credential check.
	if _, _, err := svc.CheckPassword(ctx, auth.SignInAttempt{Email: email, Password: "nope"}); err == nil {
		t.Error("CheckPassword must reject a wrong password")
	}
	u, _, err := svc.CheckPassword(ctx, auth.SignInAttempt{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}

	raw, err := svc.CreateLoginSession(ctx, u.ID, "", "test-agent")
	if err != nil {
		t.Fatalf("CreateLoginSession: %v", err)
	}
	got, err := svc.ResolveLoginSession(ctx, raw)
	if err != nil || got != u.ID {
		t.Fatalf("ResolveLoginSession = %v, %v; want %v", got, err, u.ID)
	}
	// A bogus cookie value never resolves.
	if _, err := svc.ResolveLoginSession(ctx, "not-a-session"); err == nil {
		t.Error("a bogus session value must not resolve")
	}
	// Hosted logout invalidates it.
	if err := svc.RevokeLoginSession(ctx, raw); err != nil {
		t.Fatalf("RevokeLoginSession: %v", err)
	}
	if _, err := svc.ResolveLoginSession(ctx, raw); err == nil {
		t.Error("a revoked session must not resolve")
	}
}

// Repeated wrong-password logins lock the account; once locked, even the
// correct password is refused (429). A successful login resets the counter.
func TestLoginLockout(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	email := uniqueSlug("lock") + "@example.com"

	if _, _, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}

	// A few failures then a success must NOT lock (counter resets on success).
	for i := 0; i < 3; i++ {
		if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("wrong password should fail")
		}
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("correct password before lockout should succeed: %v", err)
	}

	// Now exhaust the threshold with consecutive failures.
	for i := 0; i < 5; i++ {
		if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("wrong password should fail")
		}
	}
	// Locked: even the correct password is refused with 429.
	_, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err == nil {
		t.Fatal("account should be locked after repeated failures")
	}
	if e := errs.As(err); e == nil || e.Code != errs.ErrAuthAccountLocked.Code {
		t.Errorf("locked login should be an account-locked error, got %v", err)
	}
}

// OIDC authorization_code issues a refresh token; the refresh_token grant rotates
// it, and replaying a consumed refresh token is treated as theft (revokes the chain).
func TestOIDCRefreshTokenRotateReuse(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("rp")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	addTenantMembership(t, ctx, userID, tenantID)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)

	redirectURI := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID:     tenantID,
		Name:         "RP",
		RedirectURIs: []string{redirectURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("authorization_code exchange should return a refresh_token")
	}

	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == "" || rotated.RefreshToken == issued.RefreshToken {
		t.Fatal("refresh_token grant should rotate the token")
	}
	if rotated.AccessToken == "" {
		t.Fatal("refresh_token grant should mint a new access token")
	}

	// Replaying the consumed refresh token is theft → revoke the chain.
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Fatal("reusing a consumed refresh token should fail")
	}
	// ...so the freshly-rotated token is dead too.
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken, ""); err == nil {
		t.Fatal("rotated token must fail after reuse revokes the chain")
	}
}

// RFC 8707: a resource indicator bound at authorization_code exchange must
// survive a refresh_token rotation (the access token's audience keeps
// carrying it) rather than silently reverting to the platform-only audience.
// An explicit resource on the refresh call overrides the originally-bound one.
func TestOIDCRefreshTokenPreservesResourceBinding(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("oidc-res"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("rp")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	addTenantMembership(t, ctx, userID, tenantID)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)

	redirectURI := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID:     tenantID,
		Name:         "RP",
		RedirectURIs: []string{redirectURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	const mcpResource = "https://mcp.example.com"
	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", mcpResource)
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	claims, err := issuer.VerifyAccess(issued.AccessToken)
	if err != nil || !slices.Contains([]string(claims.Audience), mcpResource) {
		t.Fatalf("initial access token audience = %v (err %v), want to include %q", claims, err, mcpResource)
	}

	// Refresh with no resource param — the originally-bound resource carries forward.
	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	claims, err = issuer.VerifyAccess(rotated.AccessToken)
	if err != nil || !slices.Contains([]string(claims.Audience), mcpResource) {
		t.Fatalf("rotated access token audience = %v (err %v), want to still include %q", claims, err, mcpResource)
	}

	// An explicit resource on the refresh call switches the bound resource.
	const otherResource = "https://other.example.com"
	rotated2, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken, otherResource)
	if err != nil {
		t.Fatalf("refresh (explicit resource): %v", err)
	}
	claims, err = issuer.VerifyAccess(rotated2.AccessToken)
	if err != nil || !slices.Contains([]string(claims.Audience), otherResource) || slices.Contains([]string(claims.Audience), mcpResource) {
		t.Fatalf("re-refreshed access token audience = %v (err %v), want only %q", claims, err, otherResource)
	}
}

// End-to-end OpenID CIBA (poll mode): a client with login_hint starts a
// backchannel request, the user sees and approves it via the pending/decision
// endpoints, and the client's poll then succeeds — mirroring the device
// grant's rotate/reuse-safety shape but resolved via login_hint up front
// instead of a human-typed code.
func TestCIBABackchannelFlow(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("ciba"))
	userEmail := uniqueSlug("ciba") + "@example.com"
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, userEmail).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "CIBA Client", RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes: []string{"refresh_token", "urn:openid:params:grant-type:ciba"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Polling before any decision is authorization_pending.
	authResp, err := svc.BackchannelAuthorize(ctx, client.ClientID, secret, userEmail, "", "Approve $50 payment")
	if err != nil {
		t.Fatalf("backchannel authorize: %v", err)
	}
	if authResp.AuthReqID == "" {
		t.Fatal("missing auth_req_id")
	}
	// BackchannelToken's pending/denied/expired errors are oauthError, an
	// unexported type (device.go) rendered as "<code>: <description>" by
	// Error() — checked via the string, since it isn't accessible cross-package.
	if _, err := svc.BackchannelToken(ctx, client.ClientID, authResp.AuthReqID); err == nil {
		t.Fatal("token poll before decision should fail")
	} else if !strings.Contains(err.Error(), "authorization_pending") {
		t.Fatalf("poll before decision: err = %v, want authorization_pending", err)
	}

	pending, err := svc.ListPendingCIBA(ctx, userID)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %+v (err %v), want exactly 1", pending, err)
	}
	if pending[0].ClientName != "CIBA Client" || pending[0].BindingMessage == nil || *pending[0].BindingMessage != "Approve $50 payment" {
		t.Fatalf("pending request = %+v", pending[0])
	}

	// A different user can't decide someone else's request.
	otherUser := createUserIn(t, ctx, tenantID)
	if err := svc.DecideBackchannel(ctx, otherUser, pending[0].ID, true); err == nil {
		t.Fatal("a different user must not be able to decide this request")
	}

	if err := svc.DecideBackchannel(ctx, userID, pending[0].ID, true); err != nil {
		t.Fatalf("decide: %v", err)
	}
	// Bypass the CIBA interval throttle: the pre-decision poll above just set
	// last_polled_at, so a poll now (well under the 5s interval) correctly
	// returns slow_down (QID-16 — the test previously failed here because it
	// polled back-to-back). Push last_polled_at into the past, mirroring the
	// device grant's resetPollClock, so this test can poll without waiting out
	// the real interval. The slow_down behavior itself is exercised separately.
	resetCIBAPollClock(t, ctx, authResp.AuthReqID)
	resp, err := svc.BackchannelToken(ctx, client.ClientID, authResp.AuthReqID)
	if err != nil {
		t.Fatalf("token poll after approval: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatalf("expected a full token pair, got %+v", resp)
	}
	claims, err := issuer.VerifyAccess(resp.AccessToken)
	if err != nil || claims.Subject != userID.String() {
		t.Fatalf("issued token subject = %v (err %v), want %v", claims, err, userID)
	}

	// The auth_req_id is one-time.
	resetCIBAPollClock(t, ctx, authResp.AuthReqID)
	if _, err := svc.BackchannelToken(ctx, client.ClientID, authResp.AuthReqID); err == nil {
		t.Fatal("reusing a consumed auth_req_id should fail")
	}
}

// resetCIBAPollClock pushes a CIBA request's last_polled_at into the past so a
// test can poll BackchannelToken back-to-back without tripping the interval
// throttle (slow_down). Mirrors device_test.go's resetPollClock; keyed on the
// auth_req_id hash the same way BackchannelToken looks the row up.
func resetCIBAPollClock(t *testing.T, ctx context.Context, rawAuthReqID string) {
	t.Helper()
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_ciba_requests SET last_polled_at = NOW() - INTERVAL '1 hour' WHERE auth_req_id_hash = $1`,
		codes.Hash(rawAuthReqID)); err != nil {
		t.Fatalf("reset CIBA poll clock: %v", err)
	}
}

// Shadow-AI discovery: a client that picks up a machine grant type
// (client_credentials) surfaces as an unreviewed candidate, ranked by live
// (active) refresh-token count, and reviewing it removes it from the list.
func TestShadowAIDiscoveryAndReview(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("shadow"))
	reviewer := createUserIn(t, ctx, tenantID)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// A plain human-login client (authorization_code/refresh_token only) must
	// never appear as a shadow-AI candidate.
	humanClient, _, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "Web App", RedirectURIs: []string{"https://app.example/cb"},
	})
	if err != nil {
		t.Fatalf("register human client: %v", err)
	}
	// A client that also picked up client_credentials is a candidate.
	shadowClient, _, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "Sideways Automation", RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"},
	})
	if err != nil {
		t.Fatalf("register shadow client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	_ = humanClient

	candidates, err := svc.ShadowAICandidates(ctx, tenantID)
	if err != nil {
		t.Fatalf("shadow ai candidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].ID != shadowClient.ID {
		t.Fatalf("candidates = %+v, want exactly the sideways-automation client", candidates)
	}

	if err := svc.ReviewShadowAIClient(ctx, tenantID, shadowClient.ID, reviewer); err != nil {
		t.Fatalf("review: %v", err)
	}
	candidates, err = svc.ShadowAICandidates(ctx, tenantID)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("candidates after review = %+v (err %v), want none", candidates, err)
	}
}

// RFC 8693 token-exchange also supports an RFC 8707 resource indicator — the
// MCP delegation case: an agent-delegated (act-claim) token scoped to one
// specific downstream resource server.
func TestOIDCTokenExchangeBindsResource(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("oidc-te"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("rp")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID:     tenantID,
		Name:         "Agent client",
		RedirectURIs: []string{"https://app.example/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	subjectAccess, _, err := issuer.IssueAccess(userID, tenantID, uuid.New(), "doc.read")
	if err != nil {
		t.Fatalf("issue subject token: %v", err)
	}

	// RFC 8693 delegation: the actor_token is a real, verifiable access token
	// representing the acting party (the agent). Its subject flows into the
	// exchanged token's `act.sub`. Passing a bare identifier string here fails
	// VerifyAccess (QID-15 — the test previously passed the literal "agent-123",
	// which the actor-token verification correctly rejected as not-a-token).
	agentID := uuid.New()
	actorAccess, _, err := issuer.IssueAccess(agentID, tenantID, uuid.New(), "")
	if err != nil {
		t.Fatalf("issue actor token: %v", err)
	}

	const mcpResource = "https://mcp.example.com"
	resp, err := svc.TokenExchange(ctx, client.ClientID, secret, subjectAccess, "", "", "", actorAccess, "", mcpResource)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	claims, err := issuer.VerifyAccess(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify exchanged token: %v", err)
	}
	if !slices.Contains([]string(claims.Audience), mcpResource) {
		t.Fatalf("exchanged access token audience = %v, want to include %q", claims.Audience, mcpResource)
	}
	if claims.Act == nil || claims.Act.Subject != agentID.String() {
		t.Fatalf("exchanged access token should carry the act claim with the actor's subject %q, got %+v", agentID, claims.Act)
	}
}

// OIDC token introspection (RFC 7662) reports access & refresh tokens active,
// and revocation (RFC 7009) flips a refresh token to inactive.
func TestOIDCRevokeAndIntrospect(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("rp")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", RedirectURIs: []string{redirectURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}

	// Access token introspects active.
	if r, err := svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, ""); err != nil || r["active"] != true {
		t.Fatalf("access token should be active: %+v err=%v", r, err)
	}
	// Refresh token introspects active.
	if r, err := svc.Introspect(ctx, client.ClientID, secret, issued.RefreshToken, "refresh_token"); err != nil || r["active"] != true {
		t.Fatalf("refresh token should be active: %+v err=%v", r, err)
	}
	// Bad client auth is rejected.
	if _, err := svc.Introspect(ctx, client.ClientID, "wrong-secret", issued.AccessToken, ""); err == nil {
		t.Error("introspect with a bad client secret must fail")
	}
	// A garbage token is simply inactive (not an error).
	if r, err := svc.Introspect(ctx, client.ClientID, secret, "not-a-real-token", ""); err != nil || r["active"] != false {
		t.Errorf("unknown token should be inactive: %+v err=%v", r, err)
	}

	// Revoke the refresh token → now inactive, and the refresh grant fails.
	if err := svc.RevokeToken(ctx, client.ClientID, secret, issued.RefreshToken, "refresh_token"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r, err := svc.Introspect(ctx, client.ClientID, secret, issued.RefreshToken, "refresh_token"); err != nil || r["active"] != false {
		t.Errorf("revoked refresh token should be inactive: %+v err=%v", r, err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("a revoked refresh token must not be redeemable")
	}
	// Revoking an unknown token is still a success (RFC 7009).
	if err := svc.RevokeToken(ctx, client.ClientID, secret, "unknown-token", ""); err != nil {
		t.Errorf("revoking an unknown token should succeed: %v", err)
	}
}

// OIDC consent: a client has no consent initially, GrantConsent records the
// approved scopes (subset checks honoured), and Authorize derives the tenant
// from the client and mints a code.
func TestOIDCConsentAndAuthorize(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("rp")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, _, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", RedirectURIs: []string{redirectURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// No consent yet.
	if has, err := svc.HasConsent(ctx, userID, client.ClientID, []string{"openid"}); err != nil || has {
		t.Fatalf("expected no consent initially: has=%v err=%v", has, err)
	}
	// Grant openid+profile.
	if err := svc.GrantConsent(ctx, userID, client.ClientID, []string{"openid", "profile"}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	if has, err := svc.HasConsent(ctx, userID, client.ClientID, []string{"openid"}); err != nil || !has {
		t.Errorf("openid should be consented: has=%v err=%v", has, err)
	}
	// A scope outside the grant is not covered.
	if has, err := svc.HasConsent(ctx, userID, client.ClientID, []string{"openid", "email"}); err != nil || has {
		t.Errorf("email should not be consented: has=%v err=%v", has, err)
	}

	// Authorize derives the tenant from the client and mints a code.
	code, gotTenant, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if code == "" || gotTenant != tenantID {
		t.Errorf("authorize: code=%q tenant=%v want tenant=%v", code, gotTenant, tenantID)
	}
}

// TestHostedAuthorizeConsentFlow drives the whole hosted OIDC flow over real
// HTTP with a cookie jar: authorize (no session → login redirect), establish the
// SSO cookie via /v1/auth/session, authorize again (→ consent redirect), approve
// the consent decision (→ code), exchange the code for tokens, and confirm a
// second authorize skips consent and bounces straight back to the RP.
func TestHostedAuthorizeConsentFlow(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	// A user with a password and an explicit membership in the client's tenant.
	authSvc, _ := newAuth()
	email := uniqueSlug("hosted") + "@example.com"
	_, signedUp, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	// An OIDC client in a tenant.
	oidcSvc := oidc.NewService(testPool, mustIssuer())
	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
	addTenantMembership(t, ctx, signedUp.ID, tenantID)
	redirectURI := "https://app.example/cb"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := oidcSvc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", RedirectURIs: []string{redirectURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Router: the hosted auth-session endpoint + the browser-facing OIDC endpoints.
	authH := &auth.Handler{Service: authSvc, Validate: validator.New(validator.WithRequiredStructEnabled())}
	oidcH := &oidc.Handler{Service: oidcSvc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		oidcH.MountBrowser(r)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{
		Jar: jar,
		// Capture 302s instead of following them (the redirects target the
		// external login app / RP, not our test server).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	authorizeURL := func() string {
		q := url.Values{
			"client_id":    {client.ClientID},
			"redirect_uri": {redirectURI},
			"scope":        {"openid"},
			"state":        {"xyz"},
		}
		return srv.URL + "/v1/oauth/authorize?" + q.Encode()
	}
	mustGet := func(u string) *http.Response {
		resp, err := hc.Get(u)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		return resp
	}
	mustPostJSON := func(path string, payload any) *http.Response {
		b, _ := json.Marshal(payload)
		resp, err := hc.Post(srv.URL+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	// 1) No SSO cookie → redirect to the hosted login.
	resp := mustGet(authorizeURL())
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "login.test/login") {
		t.Fatalf("want redirect to hosted login, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// 2) Establish the SSO session (Set-Cookie qe_ls lands in the jar).
	resp = mustPostJSON("/v1/auth/session", map[string]string{"email": email, "password": "Kx7mQ2vLp9Wz"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/v1/auth/session status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 3) Authorize with a session but no consent → redirect to the consent screen.
	resp = mustGet(authorizeURL())
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "login.test/consent") {
		t.Fatalf("want redirect to consent, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	// 4) Approve the consent → JSON with the RP redirect carrying the code.
	resp = mustPostJSON("/v1/oauth/authorize/decision", map[string]any{
		"approve": true, "client_id": client.ClientID, "redirect_uri": redirectURI,
		"scope": "openid", "state": "xyz",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decision status %d", resp.StatusCode)
	}
	var decResp struct {
		Redirect string `json:"redirect"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&decResp)
	resp.Body.Close()
	dest, _ := url.Parse(decResp.Redirect)
	code := dest.Query().Get("code")
	if code == "" || dest.Query().Get("state") != "xyz" {
		t.Fatalf("decision redirect missing code/state: %q", decResp.Redirect)
	}

	// 5) The code exchanges for tokens — proves the hosted flow produced a valid one.
	issued, err := oidcSvc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if issued.AccessToken == "" {
		t.Fatal("hosted-flow code yielded no access token")
	}

	// 6) Consent is remembered: a second authorize skips the screen and bounces
	// straight back to the RP with a fresh code.
	resp = mustGet(authorizeURL())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), redirectURI) {
		t.Fatalf("consented authorize should redirect to RP, got %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()
}

// TestEndSessionLogout verifies RP-Initiated Logout: it clears the SSO session
// and redirects to a registered post_logout_redirect_uri (carrying state); a
// subsequent authorize then bounces back to the hosted login.
func TestEndSessionLogout(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	authSvc, _ := newAuth()
	email := uniqueSlug("logout") + "@example.com"
	if _, _, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}

	oidcSvc := oidc.NewService(testPool, mustIssuer())
	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
	redirectURI := "https://app.example/cb"
	postLogout := "https://app.example/after-logout"
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, _, err := oidcSvc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP",
		RedirectURIs:   []string{redirectURI},
		PostLogoutURIs: []string{postLogout},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	authH := &auth.Handler{Service: authSvc, Validate: validator.New(validator.WithRequiredStructEnabled())}
	oidcH := &oidc.Handler{Service: oidcSvc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		oidcH.MountBrowser(r)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Establish the SSO session.
	body, _ := json.Marshal(map[string]string{"email": email, "password": "Kx7mQ2vLp9Wz"})
	resp, err := hc.Post(srv.URL+"/v1/auth/session", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("session: %v (status %v)", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Logout with a registered post_logout_redirect_uri → redirected there.
	q := url.Values{"client_id": {client.ClientID}, "post_logout_redirect_uri": {postLogout}, "state": {"s1"}}
	resp, err = hc.Get(srv.URL + "/v1/oauth/logout?" + q.Encode())
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	loc := resp.Header.Get("Location")
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, postLogout) || !strings.Contains(loc, "state=s1") {
		t.Fatalf("logout redirect = %d %q, want %s?state=s1", resp.StatusCode, loc, postLogout)
	}

	// Session cleared: authorize now bounces back to the hosted login.
	aq := url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirectURI}, "scope": {"openid"}}
	resp, err = hc.Get(srv.URL + "/v1/oauth/authorize?" + aq.Encode())
	if err != nil {
		t.Fatalf("authorize after logout: %v", err)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.Contains(loc, "login.test/login") {
		t.Fatalf("after logout, authorize should redirect to login, got %q", loc)
	}

	// An unregistered post_logout_redirect_uri is refused → hosted logged-out page.
	q2 := url.Values{"client_id": {client.ClientID}, "post_logout_redirect_uri": {"https://evil.example/x"}}
	resp, err = hc.Get(srv.URL + "/v1/oauth/logout?" + q2.Encode())
	if err != nil {
		t.Fatalf("logout(evil): %v", err)
	}
	loc = resp.Header.Get("Location")
	resp.Body.Close()
	if !strings.Contains(loc, "login.test/logged-out") {
		t.Fatalf("unregistered post-logout uri should go to logged-out page, got %q", loc)
	}
}

// fakeIdP stands up an httptest server that plays a discovery-based OIDC
// provider: a discovery document plus token + userinfo endpoints.
func fakeIdP(t *testing.T) *httptest.Server {
	return fakeIdPWithUserinfo(t, `{"sub":"idp-subject-123","email":"social-user@example.com","email_verified":true,"name":"Social User"}`)
}

func fakeIdPWithUserinfo(t *testing.T, userinfo string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"authorization_endpoint":%q,"token_endpoint":%q,"userinfo_endpoint":%q}`,
			base+"/authorize", base+"/token", base+"/userinfo")
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fake-access-token","token_type":"Bearer"}`)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, userinfo)
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

// The social OIDC login flow against a fake IdP: start stores PKCE state, the
// callback provisions the user + external identity and mints a one-time code,
// and that code exchanges for a token pair exactly once.
func TestSocialOIDCLoginFlow(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	idp := fakeIdP(t)
	defer idp.Close()

	tenantID := createTenant(t, ctx, uniqueSlug("soc"))
	setSelfRegistration(t, ctx, tenantID, true) // this flow provisions a new account
	provider := "testidp"
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
		VALUES ($1, $2, 'cid', 'csecret', $3)
	`, tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
		t.Fatalf("insert provider: %v", err)
	}

	authSvc, _ := newAuth()
	svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
	svc.SetCipher(testEnvelope(t))

	redirectURI := "http://api.local/v1/social/" + provider + "/callback"
	const wantReturnTo = "https://app.example/oauth/authorize?client_id=rp"
	// Mirror the production wiring: return_to is validated against an origin
	// allowlist, because the callback sets the SSO cookie before redirecting
	// and an unvalidated value is an open redirect on the auth domain.
	svc.SetAllowedReturnOrigins("https://app.example")
	authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), redirectURI, wantReturnTo)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	var storedSecret string
	var secretCiphertext, secretNonce []byte
	if err := testPool.QueryRow(ctx, `
		SELECT client_secret, client_secret_ct, client_secret_nonce
		FROM tenant.social_providers WHERE tenant_id = $1 AND provider = $2
	`, tenantID, provider).Scan(&storedSecret, &secretCiphertext, &secretNonce); err != nil {
		t.Fatalf("read migrated provider secret: %v", err)
	}
	if storedSecret != "" || len(secretCiphertext) == 0 || len(secretNonce) == 0 {
		t.Fatalf("social provider secret must be ciphertext-only: plaintext=%q ciphertext=%d nonce=%d", storedSecret, len(secretCiphertext), len(secretNonce))
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorize URL missing state")
	}
	if u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("expected PKCE S256 challenge")
	}

	res, err := svc.CompleteCallback(ctx, provider, state, "upstream-auth-code")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if res.Code == "" {
		t.Fatal("callback should return a one-time code")
	}
	// The hosted return_to is threaded through the OAuth round-trip so the
	// callback can bounce back to /oauth/authorize after setting the SSO cookie.
	if res.ReturnTo != wantReturnTo {
		t.Errorf("ReturnTo = %q, want %q", res.ReturnTo, wantReturnTo)
	}
	if res.UserID == uuid.Nil {
		t.Error("callback should resolve a user id")
	}

	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = 'idp-subject-123'
	`, tenantID, provider).Scan(&n); err != nil || n != 1 {
		t.Fatalf("external identity rows = %d (err %v), want 1", n, err)
	}

	pair, err := svc.ExchangeLogin(ctx, res.Code, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("exchange should return access + refresh tokens")
	}

	// One-time: a second exchange of the same code must fail.
	if _, err := svc.ExchangeLogin(ctx, res.Code, "1.2.3.4", "test-agent"); err == nil {
		t.Fatal("reusing a social login code should fail")
	}
}

func TestSocialUnverifiedEmailCannotAutoLink(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	victimEmail := uniqueSlug("social-victim") + "@example.com"
	idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":"attacker-subject","email":%q,"email_verified":false,"name":"Attacker"}`, victimEmail))
	defer idp.Close()
	tenantID := createTenant(t, ctx, uniqueSlug("social-unverified"))
	victimID := createUserInTenant(t, ctx, tenantID)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET email = $2 WHERE id = $1`, victimID, victimEmail); err != nil {
		t.Fatalf("set victim email: %v", err)
	}
	authService, _ := newAuth()
	service := social.NewService(testPool, authService, "http://app.local", egress.DevelopmentPolicy())
	service.SetCipher(testEnvelope(t))
	if _, err := service.UpsertProvider(ctx, social.CreateProviderInput{
		TenantID: tenantID, Provider: "unverified", ClientID: "cid", ClientSecret: "secret",
		DiscoveryURL: idp.URL + "/.well-known/openid-configuration",
	}); err != nil {
		t.Fatalf("register social provider: %v", err)
	}
	authorizeURL, err := service.BeginLogin(ctx, "unverified", tenantID.String(), "http://api.local/v1/social/unverified/callback", "")
	if err != nil {
		t.Fatalf("begin unverified login: %v", err)
	}
	parsed, _ := url.Parse(authorizeURL)
	_, err = service.CompleteCallback(ctx, "unverified", parsed.Query().Get("state"), "code")
	if !errors.Is(err, errs.ErrSocialEmailUnverified) {
		t.Fatalf("unverified email collision error = %v", err)
	}
	var links int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = 'unverified' AND subject = 'attacker-subject'
	`, tenantID).Scan(&links); err != nil {
		t.Fatalf("count unverified links: %v", err)
	}
	if links != 0 {
		t.Fatalf("unverified provider created %d external identity links", links)
	}
}

func TestSocialExplicitLinkAllowsUnverifiedEmailWithoutAutoMatching(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	idp := fakeIdPWithUserinfo(t, `{"sub":"explicit-subject","email":"unverified@example.com","email_verified":false,"name":"Explicit User"}`)
	defer idp.Close()
	authService, _ := newAuth()
	service := social.NewService(testPool, authService, "http://app.local", egress.DevelopmentPolicy())
	service.SetPlatformProvider("explicit", "cid", "secret", idp.URL+"/.well-known/openid-configuration")
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, uniqueSlug("explicit-owner")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create explicit-link owner: %v", err)
	}
	redirectURI := "http://api.local/v1/social/explicit/callback"
	linkURL, err := service.BeginPlatformLink(ctx, "explicit", redirectURI, userID)
	if err != nil {
		t.Fatalf("begin explicit link: %v", err)
	}
	parsed, _ := url.Parse(linkURL)
	linked, err := service.CompletePlatformCallback(ctx, "explicit", parsed.Query().Get("state"), "link-code")
	if err != nil || !linked.Linked {
		t.Fatalf("complete explicit link: result=%+v err=%v", linked, err)
	}
	var storedEmail *string
	if err := testPool.QueryRow(ctx, `
		SELECT email FROM auth.platform_social_identities
		WHERE provider = 'explicit' AND subject = 'explicit-subject' AND user_id = $1
	`, userID).Scan(&storedEmail); err != nil {
		t.Fatalf("load explicit identity: %v", err)
	}
	if storedEmail != nil {
		t.Fatalf("explicit link persisted unverified email %q", *storedEmail)
	}

	loginURL, err := service.BeginPlatformLogin(ctx, "explicit", redirectURI, false)
	if err != nil {
		t.Fatalf("begin linked subject login: %v", err)
	}
	parsed, _ = url.Parse(loginURL)
	login, err := service.CompletePlatformCallback(ctx, "explicit", parsed.Query().Get("state"), "login-code")
	if err != nil || login.LoginCode == "" {
		t.Fatalf("existing subject login should survive missing assurance: result=%+v err=%v", login, err)
	}
}

func TestAppleLoginPersistsOnlyNonceHash(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	service := social.NewService(testPool, nil, "https://app.example", egress.DevelopmentPolicy())
	service.SetPlatformApple("com.qeet.test", "TEAMID", "KEYID", "unused-for-begin")
	authorizeURL, err := service.BeginPlatformLogin(ctx, "apple", "https://api.example/v1/social/apple/callback", false)
	if err != nil {
		t.Fatalf("begin Apple login: %v", err)
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse Apple authorize URL: %v", err)
	}
	nonce := parsed.Query().Get("nonce")
	state := parsed.Query().Get("state")
	if nonce == "" || state == "" {
		t.Fatalf("Apple authorize URL must contain state and nonce: %s", authorizeURL)
	}
	var storedNonceHash string
	if err := testPool.QueryRow(ctx, `
		SELECT nonce_hash FROM auth.platform_social_states WHERE state_hash = $1
	`, codes.Hash(state)).Scan(&storedNonceHash); err != nil {
		t.Fatalf("load Apple state: %v", err)
	}
	if storedNonceHash != codes.Hash(nonce) || storedNonceHash == nonce {
		t.Fatalf("stored Apple nonce must be its hash, got %q", storedNonceHash)
	}
}

func TestDomainSecretsEncryptedAtRest(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("encrypted-domains"))
	box := testEnvelope(t)
	policy := egress.DevelopmentPolicy()

	authHookService := authhook.NewService(testPool, policy)
	authHookService.SetCipher(box)
	hook, err := authHookService.Create(ctx, tenantID, "http://127.0.0.1/auth-hook", "hook-secret-value", true)
	if err != nil {
		t.Fatalf("create auth hook: %v", err)
	}
	assertEncryptedColumns(t, ctx, "tenant.auth_hooks", hook.ID, "secret", "secret_ct", "secret_nonce")

	siemService := siem.NewService(testPool, policy)
	siemService.SetCipher(box)
	sink, err := siemService.Create(ctx, tenantID, "http", "http://127.0.0.1/events", "siem-token-value")
	if err != nil {
		t.Fatalf("create SIEM sink: %v", err)
	}
	assertEncryptedColumns(t, ctx, "tenant.log_sinks", sink.ID, "token", "token_ct", "token_nonce")

	authService, _ := newAuth()
	ldapService := ldap.NewService(testPool, authService, policy)
	ldapService.SetCipher(box)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin LDAP create: %v", err)
	}
	connection, err := ldapService.Create(ctx, tx, tenantID, ldap.CreateInput{
		Name: "directory", ServerURL: "ldap://127.0.0.1:389", BindDN: "cn=service,dc=example,dc=com",
		BindPassword: "ldap-password-value", BaseDN: "dc=example,dc=com",
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("create LDAP connection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit LDAP create: %v", err)
	}
	assertEncryptedColumns(t, ctx, "tenant.ldap_connections", connection.ID, "bind_password", "bind_password_ct", "bind_password_nonce")

	rotatedPassword := "rotated-ldap-password"
	tx, err = testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin LDAP update: %v", err)
	}
	if _, err := ldapService.Update(ctx, tx, connection.ID, tenantID, ldap.UpdateInput{BindPassword: &rotatedPassword}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("rotate LDAP password: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit LDAP update: %v", err)
	}
	assertEncryptedColumns(t, ctx, "tenant.ldap_connections", connection.ID, "bind_password", "bind_password_ct", "bind_password_nonce")

	legacyTenantID := createTenant(t, ctx, uniqueSlug("legacy-encrypted-domains"))
	hookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer hookServer.Close()
	var legacyHookID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.auth_hooks (tenant_id, url, secret, fail_open)
		VALUES ($1, $2, 'legacy-hook-secret', false)
		RETURNING id
	`, legacyTenantID, hookServer.URL).Scan(&legacyHookID); err != nil {
		t.Fatalf("seed legacy auth hook: %v", err)
	}
	if _, err := authHookService.Run(ctx, legacyTenantID, uuid.New(), "legacy@example.com"); err != nil {
		t.Fatalf("run legacy auth hook: %v", err)
	}
	assertEncryptedColumns(t, ctx, "tenant.auth_hooks", legacyHookID, "secret", "secret_ct", "secret_nonce")

	var legacySinkID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO tenant.log_sinks
		    (tenant_id, type, endpoint, token, cursor_created_at, cursor_id)
		VALUES ($1, 'http', 'http://127.0.0.1/events', 'legacy-siem-token',
		        NOW(), '00000000-0000-0000-0000-000000000000')
		RETURNING id
	`, legacyTenantID).Scan(&legacySinkID); err != nil {
		t.Fatalf("seed legacy SIEM sink: %v", err)
	}
	runCtx, cancelRun := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		siemService.Run(runCtx)
		close(done)
	}()
	deadline := time.NewTimer(2 * time.Second)
	poll := time.NewTicker(10 * time.Millisecond)
	migrated := false
	for !migrated {
		select {
		case <-deadline.C:
			cancelRun()
			<-done
			t.Fatal("SIEM legacy token was not migrated")
		case <-poll.C:
			var plaintext string
			var ciphertext, nonce []byte
			if err := testPool.QueryRow(ctx, `
				SELECT token, token_ct, token_nonce FROM tenant.log_sinks WHERE id = $1
			`, legacySinkID).Scan(&plaintext, &ciphertext, &nonce); err != nil {
				cancelRun()
				<-done
				t.Fatalf("read legacy SIEM migration: %v", err)
			}
			migrated = plaintext == "" && len(ciphertext) > 0 && len(nonce) > 0
		}
	}
	poll.Stop()
	deadline.Stop()
	cancelRun()
	<-done
}

func TestSAMLRequestCorrelationAndConcurrentReplay(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("saml-replay"))
	_, certPEM, err := saml.GenerateIdPKeyPEM("Replay Test IdP")
	if err != nil {
		t.Fatalf("generate IdP certificate: %v", err)
	}
	service := saml.NewService(testPool, nil, "https://app.example")
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin SAML connection: %v", err)
	}
	connection, err := service.Create(ctx, tx, tenantID, saml.CreateInput{
		Name: "Replay Test", IdpEntityID: "https://idp.example/entity",
		IdpSSOURL: "https://idp.example/sso", IdpCertificate: certPEM, Status: "active",
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("create SAML connection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit SAML connection: %v", err)
	}

	handler := &saml.Handler{Service: service}
	router := chi.NewRouter()
	handler.MountPublic(router)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/saml/login/"+connection.ID.String(), nil)
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusFound {
		t.Fatalf("SAML login status = %d, want 302: %s", recorder.Code, recorder.Body.String())
	}
	var requestID string
	if err := testPool.QueryRow(ctx, `
		SELECT request_id FROM auth.saml_authn_requests WHERE connection_id = $1
	`, connection.ID).Scan(&requestID); err != nil {
		t.Fatalf("load persisted AuthnRequest: %v", err)
	}

	const contenders = 16
	start := make(chan struct{})
	results := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- service.ConsumeValidatedResponse(ctx, connection.ID, requestID, "_response-once", []string{"_assertion-once"}, false)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes, replays := 0, 0
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, errs.ErrSAMLReplayDetected):
			replays++
		default:
			t.Fatalf("unexpected replay result: %v", result)
		}
	}
	if successes != 1 || replays != contenders-1 {
		t.Fatalf("concurrent SAML consumption: successes=%d replays=%d", successes, replays)
	}
	if err := service.ConsumeValidatedResponse(ctx, connection.ID, "_unknown-request", "_new-response", []string{"_new-assertion"}, false); !errors.Is(err, errs.ErrSAMLRequestCorrelation) {
		t.Fatalf("unknown InResponseTo error = %v, want correlation failure", err)
	}

	// IdP-initiated: refused by default, accepted once the connection opts in,
	// and still covered by replay protection either way.
	if err := service.ConsumeValidatedResponse(ctx, connection.ID, "", "_idp-response", []string{"_idp-assertion"}, false); !errors.Is(err, errs.ErrSAMLRequestCorrelation) {
		t.Fatalf("IdP-initiated response error = %v, want correlation failure", err)
	}
	if err := service.ConsumeValidatedResponse(ctx, connection.ID, "", "_idp-response", []string{"_idp-assertion"}, true); err != nil {
		t.Fatalf("opted-in IdP-initiated response error = %v, want accepted", err)
	}
	if err := service.ConsumeValidatedResponse(ctx, connection.ID, "", "_idp-response", []string{"_idp-assertion"}, true); !errors.Is(err, errs.ErrSAMLReplayDetected) {
		t.Fatalf("replayed IdP-initiated response error = %v, want replay detected", err)
	}
}

func TestSAMLACSRejectsSignedResponseReplay(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("saml-signed-replay"))
	userID := createUserInTenant(t, ctx, tenantID)
	keyPEM, certPEM, err := saml.GenerateIdPKeyPEM("Signed Replay Test")
	if err != nil {
		t.Fatalf("generate SAML signing material: %v", err)
	}
	authService, _ := newAuth()
	spService := saml.NewService(testPool, authService, "https://app.example")
	idpService, err := saml.NewIdP(testPool, keyPEM, certPEM, "https://id.example", fixedSAMLSession{userID: userID})
	if err != nil {
		t.Fatalf("create SAML IdP: %v", err)
	}

	tx, _ := testPool.Begin(ctx)
	connection, err := spService.Create(ctx, tx, tenantID, saml.CreateInput{
		Name: "Loopback IdP", IdpEntityID: "https://id.example/saml/idp",
		IdpSSOURL: "https://id.example/saml/idp/sso", IdpCertificate: certPEM,
		EmailAttribute: "email", NameAttribute: "name", Status: "active",
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("create SAML connection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit SAML connection: %v", err)
	}
	entityID := "https://id.example/saml/metadata/" + connection.ID.String()
	acsURL := "https://id.example/saml/acs/" + connection.ID.String()
	tx, _ = testPool.Begin(ctx)
	if _, err := idpService.CreateSP(ctx, tx, tenantID, saml.CreateSPInput{
		Name: "Loopback SP", EntityID: entityID, ACSURL: acsURL, Status: "active",
	}); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("create SAML service provider: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit SAML service provider: %v", err)
	}

	handler := &saml.Handler{Service: spService, IdP: idpService}
	router := chi.NewRouter()
	handler.MountPublic(router)
	loginRecorder := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodGet, "https://id.example/saml/login/"+connection.ID.String(), nil)
	router.ServeHTTP(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusFound {
		t.Fatalf("SAML login status = %d: %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	redirectURL, err := url.Parse(loginRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	samlRequest := redirectURL.Query().Get("SAMLRequest")
	if samlRequest == "" {
		t.Fatal("IdP redirect has no SAMLRequest")
	}

	idpRecorder := httptest.NewRecorder()
	idpRequest := httptest.NewRequest(http.MethodGet, "https://id.example/saml/idp/sso?SAMLRequest="+url.QueryEscape(samlRequest), nil)
	idpRequest.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: "test-session"})
	router.ServeHTTP(idpRecorder, idpRequest)
	if idpRecorder.Code != http.StatusOK {
		t.Fatalf("IdP SSO status = %d: %s", idpRecorder.Code, idpRecorder.Body.String())
	}
	match := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindStringSubmatch(idpRecorder.Body.String())
	if len(match) != 2 {
		t.Fatal("IdP response form has no SAMLResponse")
	}
	encodedResponse := match[1]

	postACS := func() *httptest.ResponseRecorder {
		form := url.Values{"SAMLResponse": {encodedResponse}}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(recorder, request)
		return recorder
	}
	first := postACS()
	if first.Code != http.StatusFound {
		t.Fatalf("first ACS status = %d: %s", first.Code, first.Body.String())
	}
	second := postACS()
	if second.Code != http.StatusUnauthorized || !strings.Contains(second.Body.String(), errs.CodeSAMLReplayDetected) {
		t.Fatalf("replayed ACS response = %d %s, want replay rejection", second.Code, second.Body.String())
	}
	var loginCodes int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.saml_login_codes WHERE tenant_id = $1`, tenantID).Scan(&loginCodes); err != nil {
		t.Fatalf("count SAML login codes: %v", err)
	}
	if loginCodes != 1 {
		t.Fatalf("signed assertion replay created %d login codes, want 1", loginCodes)
	}
}

func assertEncryptedColumns(t *testing.T, ctx context.Context, table string, id uuid.UUID, plaintextColumn, ciphertextColumn, nonceColumn string) {
	t.Helper()
	query := fmt.Sprintf("SELECT %s, %s, %s FROM %s WHERE id = $1", plaintextColumn, ciphertextColumn, nonceColumn, table)
	var plaintext string
	var ciphertext, nonce []byte
	if err := testPool.QueryRow(ctx, query, id).Scan(&plaintext, &ciphertext, &nonce); err != nil {
		t.Fatalf("read encrypted columns from %s: %v", table, err)
	}
	if plaintext != "" || len(ciphertext) == 0 || len(nonce) == 0 {
		t.Fatalf("%s secret must be ciphertext-only: plaintext=%q ciphertext=%d nonce=%d", table, plaintext, len(ciphertext), len(nonce))
	}
}

// WebAuthn begin paths that don't require a real authenticator: register/begin
// stores a 'register' session + challenge; username-first login scopes
// allowCredentials to the user's stored passkeys; discoverable login stores a
// 'login_discoverable' session. (The signed finish path is covered manually in
// the browser — it needs a real authenticator.)
func TestPasskeyBeginCeremonies(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	tenantID := createTenant(t, ctx, uniqueSlug("pk"))
	email := uniqueSlug("pk") + "@example.com"
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	authSvc, _ := newAuth()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Qeet ID", RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("webauthn new: %v", err)
	}
	svc := passkey.NewService(testPool, wa, authSvc)

	sid, options, err := svc.BeginRegister(ctx, userID)
	if err != nil {
		t.Fatalf("begin register: %v", err)
	}
	if len(options.Response.Challenge) == 0 {
		t.Fatal("registration options missing a challenge")
	}
	var kind string
	if err := testPool.QueryRow(ctx, `SELECT kind FROM auth.webauthn_sessions WHERE id = $1`, sid).Scan(&kind); err != nil || kind != "register" {
		t.Fatalf("register session kind = %q (err %v), want register", kind, err)
	}

	// Seed a credential so username-first login can resolve + scope it.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, transports)
		VALUES ($1, $2, $3, 0, $4)
	`, userID, []byte("test-credential-id"), []byte("fake-public-key"), []string{"internal"}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	_, assertion, err := svc.BeginLogin(ctx, email)
	if err != nil {
		t.Fatalf("begin login (username): %v", err)
	}
	if len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("allowCredentials = %d, want 1 (loadCredentials round-trip)", len(assertion.Response.AllowedCredentials))
	}

	dsid, _, err := svc.BeginLogin(ctx, "")
	if err != nil {
		t.Fatalf("begin login (discoverable): %v", err)
	}
	if err := testPool.QueryRow(ctx, `SELECT kind FROM auth.webauthn_sessions WHERE id = $1`, dsid).Scan(&kind); err != nil || kind != "login_discoverable" {
		t.Fatalf("discoverable session kind = %q (err %v), want login_discoverable", kind, err)
	}
}

// Passkey-first signup: BeginSignup stores a pending 'signup' session (no user
// row exists yet), rejects an email already registered tenant-less, and
// BeginTenantSignup is forbidden when the tenant has no self-registration
// policy wired — the same gate RegisterInTenant uses. (The signed finish path,
// like TestPasskeyBeginCeremonies, needs a real authenticator and is covered
// manually in the browser.)
func TestPasskeySignupBegin(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	authSvc, _ := newAuth()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Qeet ID", RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("webauthn new: %v", err)
	}
	svc := passkey.NewService(testPool, wa, authSvc)

	email := uniqueSlug("pksignup") + "@example.com"
	sid, options, err := svc.BeginSignup(ctx, email, "New User")
	if err != nil {
		t.Fatalf("begin signup: %v", err)
	}
	if len(options.Response.Challenge) == 0 {
		t.Fatal("signup options missing a challenge")
	}
	var kind, pendingEmail string
	var subjectID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		SELECT kind, pending_email, subject_id FROM auth.webauthn_sessions WHERE id = $1
	`, sid).Scan(&kind, &pendingEmail, &subjectID); err != nil {
		t.Fatalf("query signup session: %v", err)
	}
	if kind != "signup" || pendingEmail != email || subjectID == uuid.Nil {
		t.Fatalf("signup session = kind=%q email=%q subject=%v, want signup/%q/non-nil", kind, pendingEmail, subjectID, email)
	}

	// A second signup for the same (tenant-less) email must conflict.
	_, _, err = svc.BeginSignup(ctx, email, "")
	if e := errs.As(err); e == nil || e.Code != errs.ErrAuthEmailExists.Code {
		t.Fatalf("begin signup (dup email): err = %v, want ErrAuthEmailExists", err)
	}

	// Tenant-scoped signup with no self-registration policy wired must be
	// forbidden — same gate as auth.Service.RegisterInTenant.
	tenantID := createTenant(t, ctx, uniqueSlug("pksignup"))
	_, _, err = svc.BeginTenantSignup(ctx, tenantID, uniqueSlug("pksignup")+"@example.com", "")
	if e := errs.As(err); e == nil || e.Code != errs.ErrAuthSelfRegistrationDisabled.Code {
		t.Fatalf("begin tenant signup (no policy): err = %v, want ErrAuthSelfRegistrationDisabled", err)
	}
}

// End-to-end Token Vault: register a provider, connect (authorization_code
// exchange), fetch a live access token (no refresh needed), then — once the
// stored token is fast-forwarded past expiry — fetch again and confirm it
// transparently refreshed via the stored refresh_token. Disconnect then
// makes the account unreachable again.
func TestTokenVaultConnectRefreshDisconnect(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("tv"))
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id
	`, tenantID, uniqueSlug("tv")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	var refreshCount int
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("mock provider: parse form: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "test-code" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-1", "refresh_token": "refresh-1",
				"token_type": "Bearer", "expires_in": 3600,
			})
		case "refresh_token":
			refreshCount++
			if r.Form.Get("refresh_token") != "refresh-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-2", "token_type": "Bearer", "expires_in": 3600,
			})
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer mock.Close()

	kp := secret.StaticKeyProvider{Key: []byte("01234567890123456789012345678901")}
	svc, err := tokenvault.NewService(ctx, testPool, kp, egress.DevelopmentPolicy())
	if err != nil {
		t.Fatalf("new token vault service: %v", err)
	}

	if _, err := svc.RegisterProvider(ctx, tenantID, tokenvault.RegisterProviderInput{
		Provider: "mock", ClientID: "cid", ClientSecret: "csecret",
		AuthorizeURL: mock.URL + "/authorize", TokenURL: mock.URL + "/token", Scopes: "read",
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}

	authorizeURL, err := svc.BeginConnect(ctx, tenantID, userID, "mock", "https://id.example.com")
	if err != nil {
		t.Fatalf("begin connect: %v", err)
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize url: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatal("authorize_url missing state")
	}
	if redirect := u.Query().Get("redirect_uri"); redirect != "https://id.example.com/v1/vault/tokens/callback" {
		t.Errorf("redirect_uri = %q, want the vault's own fixed callback", redirect)
	}

	if err := svc.FinishConnect(ctx, state, "test-code", "https://id.example.com"); err != nil {
		t.Fatalf("finish connect: %v", err)
	}
	// The state is single-use — replaying it must fail.
	if err := svc.FinishConnect(ctx, state, "test-code", "https://id.example.com"); err == nil {
		t.Fatal("reusing a consumed connect state should fail")
	}

	token, err := svc.GetAccessToken(ctx, tenantID, userID, "mock")
	if err != nil {
		t.Fatalf("get access token: %v", err)
	}
	if token != "access-1" {
		t.Fatalf("access token = %q, want access-1 (no refresh should have happened yet)", token)
	}
	if refreshCount != 0 {
		t.Fatalf("refresh happened %d times before expiry — should be 0", refreshCount)
	}

	// Fast-forward the stored token past expiry, then fetch again.
	if _, err := testPool.Exec(ctx, `
		UPDATE tenant.token_vault_grants SET expires_at = NOW() - INTERVAL '1 hour'
		WHERE tenant_id = $1 AND user_id = $2 AND provider = 'mock'
	`, tenantID, userID); err != nil {
		t.Fatalf("fast-forward expiry: %v", err)
	}
	token, err = svc.GetAccessToken(ctx, tenantID, userID, "mock")
	if err != nil {
		t.Fatalf("get access token (post-expiry): %v", err)
	}
	if token != "access-2" {
		t.Fatalf("access token after expiry = %q, want access-2 (refreshed)", token)
	}
	if refreshCount != 1 {
		t.Fatalf("refresh happened %d times, want exactly 1", refreshCount)
	}

	if err := svc.Disconnect(ctx, tenantID, userID, "mock"); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if _, err := svc.GetAccessToken(ctx, tenantID, userID, "mock"); err == nil {
		t.Fatal("GetAccessToken should fail after disconnect")
	}
}

// CreateWithOwner creates the tenant, an owner role granted all permissions, a
// membership row, and adopts the tenant as the creator's home.
func TestTenantCreateWithOwner(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, users := newAuth()

	_, u, _, err := svc.Signup(ctx, auth.SignupInput{Email: uniqueSlug("owner") + "@example.com", Password: "Kx7mQ2vLp9Wz"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}

	repo := tenant.NewRepository(testPool)
	tn, err := repo.CreateWithOwner(ctx, tenant.CreateInput{Slug: uniqueSlug("acme"), Name: "Acme"}, u.ID)
	if err != nil {
		t.Fatalf("CreateWithOwner: %v", err)
	}

	var roleName string
	var isSystem bool
	if err := testPool.QueryRow(ctx, `
		SELECT r.name, r.is_system
		FROM rbac.user_roles ur JOIN rbac.roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
	`, u.ID, tn.ID).Scan(&roleName, &isSystem); err != nil {
		t.Fatalf("owner membership not found: %v", err)
	}
	if roleName != "owner" || !isSystem {
		t.Fatalf("expected system owner role, got %q system=%v", roleName, isSystem)
	}

	// Home tenant adopted (was tenant-less at signup).
	got, err := users.Get(ctx, u.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.TenantID != tn.ID {
		t.Fatalf("home tenant = %v, want %v", got.TenantID, tn.ID)
	}
}

// Phase-1 regression: webhook subscriptions are only reachable within their
// own tenant — a foreign tenant id yields NotFound, not the row.
func TestWebhookTenantIsolation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantA := createTenant(t, ctx, uniqueSlug("a"))
	tenantB := createTenant(t, ctx, uniqueSlug("b"))

	svc := webhook.NewService(testPool, egress.DevelopmentPolicy())
	svc.SetCipher(testEnvelope(t))
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	sub, err := svc.Create(ctx, tx, webhook.CreateInput{TenantID: tenantA, URL: "https://example.com/hook", Events: []string{}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var storedSecret string
	var storedCiphertext []byte
	if err := testPool.QueryRow(ctx, `
		SELECT secret, secret_ct FROM tenant.webhook_subscriptions WHERE id = $1
	`, sub.ID).Scan(&storedSecret, &storedCiphertext); err != nil {
		t.Fatalf("inspect webhook secret storage: %v", err)
	}
	if storedSecret != "" || len(storedCiphertext) == 0 {
		t.Fatalf("webhook secret storage is not encrypted: plaintext=%q ciphertext_bytes=%d", storedSecret, len(storedCiphertext))
	}

	if _, err := svc.Get(ctx, sub.ID, tenantA); err != nil {
		t.Fatalf("owner tenant should read its subscription: %v", err)
	}
	if _, err := svc.Get(ctx, sub.ID, tenantB); !errors.Is(err, errs.ErrWebhookNotFound) {
		t.Fatalf("foreign tenant Get should be NotFound, got %v", err)
	}
}

// A permanently-failing endpoint must stop retrying once it exhausts its
// attempt budget (dead_at set), not retry forever; RetryDelivery clears
// dead_at for a manual re-send, and Sweep picks it back up.
func TestWebhookDeliveryGivesUpAfterMaxAttempts(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("wh-dlq"))

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()

	svc := webhook.NewService(testPool, egress.DevelopmentPolicy())
	svc.SetCipher(testEnvelope(t))
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	sub, err := svc.Create(ctx, tx, webhook.CreateInput{TenantID: tenantID, URL: failing.URL, Events: []string{}})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := svc.Enqueue(ctx, tenantID, "test.event", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Fast-forward attempt to one below the give-up threshold so the next
	// Sweep is the one that gives up, instead of looping 60 times here.
	if _, err := testPool.Exec(ctx, `
		UPDATE tenant.webhook_deliveries SET attempt = 59, next_attempt_at = NOW()
		WHERE subscription_id = $1
	`, sub.ID); err != nil {
		t.Fatalf("fast-forward attempt: %v", err)
	}
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	deliveries, err := svc.ListDeliveries(ctx, sub.ID, tenantID, 10)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("list deliveries: %v (err %v), want 1", deliveries, err)
	}
	d := deliveries[0]
	if d.DeadAt == nil {
		t.Fatal("delivery should be dead-lettered after exhausting attempts")
	}
	if d.Attempt != 60 {
		t.Fatalf("attempt = %d, want 60", d.Attempt)
	}

	// A second sweep must not touch a dead delivery.
	if err := svc.Sweep(ctx); err != nil {
		t.Fatalf("sweep (dead, no-op): %v", err)
	}
	deliveries, _ = svc.ListDeliveries(ctx, sub.ID, tenantID, 10)
	if deliveries[0].Attempt != 60 {
		t.Fatalf("dead delivery must not be retried by Sweep; attempt = %d", deliveries[0].Attempt)
	}

	// RetryDelivery clears dead_at and re-queues it for the next Sweep.
	if err := svc.RetryDelivery(ctx, d.ID, tenantID); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	deliveries, _ = svc.ListDeliveries(ctx, sub.ID, tenantID, 10)
	if deliveries[0].DeadAt != nil {
		t.Fatal("RetryDelivery should clear dead_at")
	}
}

// The refactored group service owns the tx and writes the audit row in it; the
// audit hash-chain must get a row, and Delete is tenant-scoped + idempotent-404.
func TestGroupServiceAuditedFlow(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("grp"))
	svc := group.NewService(testPool)
	actor := audit.Actor{Type: "system"}

	g, err := svc.Create(ctx, group.CreateInput{TenantID: tenantID, Name: "Engineering"}, actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	var audits int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events
		WHERE tenant_id = $1 AND action = 'group.created' AND resource_id = $2
	`, tenantID, g.ID).Scan(&audits); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if audits != 1 {
		t.Fatalf("expected 1 group.created audit row, got %d", audits)
	}

	if got, err := svc.List(ctx, tenantID); err != nil || len(got) != 1 {
		t.Fatalf("list = %v (err %v), want 1", got, err)
	}
	if err := svc.Delete(ctx, g.ID, tenantID, actor); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := svc.Delete(ctx, g.ID, tenantID, actor); !errors.Is(err, errs.ErrGroupNotFound) {
		t.Fatalf("second delete should be NotFound, got %v", err)
	}
}

// Every analytics projection must run against the real schema (this catches
// queries that reference missing/out-of-scope columns, like the weekly-
// activity bug). An empty tenant is fine — we only assert it doesn't error.
func TestAnalyticsOverviewRuns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("an"))
	if _, err := analytics.NewReader(testPool).Overview(ctx, tenantID); err != nil {
		t.Fatalf("analytics overview: %v", err)
	}
}

// TestSocialEmailVerifiedStatesOnProvisioning pins the three states an OIDC
// provider can put the account in, independently.
//
// Refusing to provision without a verified claim would lock out every provider
// that omits `email_verified`, so provisioning is allowed. What must not happen
// is the provider's silence being upgraded into a verified address: other flows
// treat email_verified_at as proof of control, so an unverified or absent claim
// has to land as NULL.
func TestSocialEmailVerifiedStatesOnProvisioning(t *testing.T) {
	requireDB(t)
	ctx := context.Background()

	cases := []struct {
		name         string
		claim        string // the email_verified fragment, or "" to omit it entirely
		wantVerified bool
	}{
		{"claim true", `,"email_verified":true`, true},
		{"claim false", `,"email_verified":false`, false},
		{"claim absent", ``, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueSlug("social-state") + "@example.com"
			idp := fakeIdPWithUserinfo(t, fmt.Sprintf(
				`{"sub":%q,"email":%q%s,"name":"New User"}`, uniqueSlug("sub"), email, tc.claim))
			defer idp.Close()

			tenantID := createTenant(t, ctx, uniqueSlug("social-state"))
			setSelfRegistration(t, ctx, tenantID, true) // provisioning needs open registration
			authService, _ := newAuth()
			service := social.NewService(testPool, authService, "http://app.local", egress.DevelopmentPolicy())
			service.SetCipher(testEnvelope(t))
			provider := "stateprov"
			if _, err := service.UpsertProvider(ctx, social.CreateProviderInput{
				TenantID: tenantID, Provider: provider, ClientID: "cid", ClientSecret: "secret",
				DiscoveryURL: idp.URL + "/.well-known/openid-configuration",
			}); err != nil {
				t.Fatalf("register provider: %v", err)
			}

			authorizeURL, err := service.BeginLogin(ctx, provider, tenantID.String(),
				"http://api.local/v1/social/"+provider+"/callback", "")
			if err != nil {
				t.Fatalf("begin login: %v", err)
			}
			parsed, _ := url.Parse(authorizeURL)
			if _, err := service.CompleteCallback(ctx, provider, parsed.Query().Get("state"), "code"); err != nil {
				t.Fatalf("provisioning a new account must succeed regardless of the claim, got %v", err)
			}

			var verifiedAt *time.Time
			if err := testPool.QueryRow(ctx, `
				SELECT email_verified_at FROM "user".users WHERE tenant_id = $1 AND email = $2
			`, tenantID, email).Scan(&verifiedAt); err != nil {
				t.Fatalf("read provisioned user: %v", err)
			}
			if tc.wantVerified && verifiedAt == nil {
				t.Error("a verified claim should carry through to email_verified_at")
			}
			if !tc.wantVerified && verifiedAt != nil {
				t.Error("an unverified or absent claim must NOT mark the address verified")
			}
		})
	}
}

// TestSocialAbsentEmailVerifiedCannotAdoptExistingAccount covers the takeover
// path for the third state: an omitted claim must be treated exactly like an
// explicit false when an account with that address already exists.
func TestSocialAbsentEmailVerifiedCannotAdoptExistingAccount(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	victimEmail := uniqueSlug("social-absent") + "@example.com"
	// Note: no email_verified key at all.
	idp := fakeIdPWithUserinfo(t, fmt.Sprintf(
		`{"sub":"attacker-absent","email":%q,"name":"Attacker"}`, victimEmail))
	defer idp.Close()

	tenantID := createTenant(t, ctx, uniqueSlug("social-absent"))
	victimID := createUserInTenant(t, ctx, tenantID)
	if _, err := testPool.Exec(ctx,
		`UPDATE "user".users SET email = $2 WHERE id = $1`, victimID, victimEmail); err != nil {
		t.Fatalf("set victim email: %v", err)
	}

	authService, _ := newAuth()
	service := social.NewService(testPool, authService, "http://app.local", egress.DevelopmentPolicy())
	service.SetCipher(testEnvelope(t))
	if _, err := service.UpsertProvider(ctx, social.CreateProviderInput{
		TenantID: tenantID, Provider: "absentprov", ClientID: "cid", ClientSecret: "secret",
		DiscoveryURL: idp.URL + "/.well-known/openid-configuration",
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}
	authorizeURL, err := service.BeginLogin(ctx, "absentprov", tenantID.String(),
		"http://api.local/v1/social/absentprov/callback", "")
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	parsed, _ := url.Parse(authorizeURL)
	if _, err := service.CompleteCallback(ctx, "absentprov", parsed.Query().Get("state"), "code"); !errors.Is(err, errs.ErrSocialEmailUnverified) {
		t.Fatalf("absent email_verified adopting an existing account: err = %v, want unverified", err)
	}
	var links int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM "user".external_identities
		WHERE tenant_id = $1 AND subject = 'attacker-absent'
	`, tenantID).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if links != 0 {
		t.Fatalf("a rejected adoption still created %d identity links", links)
	}
}
