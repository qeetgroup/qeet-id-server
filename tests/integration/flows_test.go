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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	secret "github.com/qeetgroup/qeet-id-server/internal/developer/credentials/secrets"
	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/tokenvault"
	"github.com/qeetgroup/qeet-id-server/internal/developer/webhooks"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/identity/groups"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/analytics"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
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
	return auth.NewService(testPool, users, issuer), users
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
	mfaSvc := mfa.NewService(testPool, "qeet", notifier.LogSender{})
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
	code, err := totp.Code(enr.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if _, err := mfaSvc.ConfirmEnroll(ctx, tx, userID, code); err != nil {
		t.Fatalf("totp confirm: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
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

	// Correct code completes the login.
	good, err := totp.Code(enr.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
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

// Admin MFA reset clears a user's enrolled factors so a locked-out user can
// re-enroll (the service method behind DELETE /v1/users/{id}/mfa).
func TestAdminResetMFA(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	users := user.NewRepository(testPool)
	svc := auth.NewService(testPool, users, mustIssuer())
	mfaSvc := mfa.NewService(testPool, "qeet", notifier.LogSender{})

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
	code, err := totp.Code(enr.Secret, time.Now())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	if _, err := mfaSvc.ConfirmEnroll(ctx, tx, userID, code); err != nil {
		t.Fatalf("totp confirm: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if ok, err := mfaSvc.IsEnrolled(ctx, userID); err != nil || !ok {
		t.Fatalf("expected enrolled before reset (ok=%v err=%v)", ok, err)
	}

	// Admin reset wipes the factors.
	rtx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	if err := mfaSvc.ResetForUser(ctx, rtx, userID); err != nil {
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
	if _, _, err := svc.CheckPassword(ctx, email, "nope"); err == nil {
		t.Error("CheckPassword must reject a wrong password")
	}
	u, _, err := svc.CheckPassword(ctx, email, "Kx7mQ2vLp9Wz")
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
	if e := errs.As(err); e == nil || e.Status != 429 {
		t.Errorf("locked login should be 429, got %v", err)
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

	// A user with a password (tenant-less is fine — authorize derives the tenant
	// from the client, not the user).
	authSvc, _ := newAuth()
	email := uniqueSlug("hosted") + "@example.com"
	if _, _, _, err := authSvc.Signup(ctx, auth.SignupInput{Email: email, Password: "Kx7mQ2vLp9Wz"}); err != nil {
		t.Fatalf("signup: %v", err)
	}

	// An OIDC client in a tenant.
	oidcSvc := oidc.NewService(testPool, mustIssuer())
	tenantID := createTenant(t, ctx, uniqueSlug("oidc"))
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
		fmt.Fprint(w, `{"sub":"idp-subject-123","email":"social-user@example.com","name":"Social User"}`)
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
	provider := "testidp"
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
		VALUES ($1, $2, 'cid', 'csecret', $3)
	`, tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
		t.Fatalf("insert provider: %v", err)
	}

	authSvc, _ := newAuth()
	svc := social.NewService(testPool, authSvc, "http://app.local")

	redirectURI := "http://api.local/v1/social/" + provider + "/callback"
	const wantReturnTo = "https://app.example/oauth/authorize?client_id=rp"
	authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), redirectURI, wantReturnTo)
	if err != nil {
		t.Fatalf("begin login: %v", err)
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
	if e := errs.As(err); e == nil || e.Code != errs.ErrConflict.Code {
		t.Fatalf("begin signup (dup email): err = %v, want ErrConflict", err)
	}

	// Tenant-scoped signup with no self-registration policy wired must be
	// forbidden — same gate as auth.Service.RegisterInTenant.
	tenantID := createTenant(t, ctx, uniqueSlug("pksignup"))
	_, _, err = svc.BeginTenantSignup(ctx, tenantID, uniqueSlug("pksignup")+"@example.com", "")
	if e := errs.As(err); e == nil || e.Code != errs.ErrForbidden.Code {
		t.Fatalf("begin tenant signup (no policy): err = %v, want ErrForbidden", err)
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
	svc, err := tokenvault.NewService(ctx, testPool, kp)
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

	svc := webhook.NewService(testPool)
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

	if _, err := svc.Get(ctx, sub.ID, tenantA); err != nil {
		t.Fatalf("owner tenant should read its subscription: %v", err)
	}
	if _, err := svc.Get(ctx, sub.ID, tenantB); !errors.Is(err, errs.ErrNotFound) {
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

	svc := webhook.NewService(testPool)
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
	if err := svc.Delete(ctx, g.ID, tenantID, actor); !errors.Is(err, errs.ErrNotFound) {
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
