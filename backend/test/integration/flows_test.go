//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/analytics"
	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/auth"
	"github.com/qeetgroup/qeet-identity/internal/group"
	"github.com/qeetgroup/qeet-identity/internal/oidc"
	"github.com/qeetgroup/qeet-identity/internal/passkey"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
	"github.com/qeetgroup/qeet-identity/internal/social"
	"github.com/qeetgroup/qeet-identity/internal/tenant"
	"github.com/qeetgroup/qeet-identity/internal/user"
	"github.com/qeetgroup/qeet-identity/internal/webhook"
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

	pair, u, brief, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "password123"})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	if u.TenantID != uuid.Nil || brief != nil || pair.TenantID != nil {
		t.Fatalf("signup should be tenant-less: tenantID=%v brief=%v pair.TenantID=%v", u.TenantID, brief, pair.TenantID)
	}

	lp, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "password123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	rotated, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: lp.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.RefreshToken == lp.RefreshToken {
		t.Fatal("refresh should rotate the token")
	}

	// Reusing the now-consumed token must fail (theft detection).
	if _, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: lp.RefreshToken}); err == nil {
		t.Fatal("reusing a consumed refresh token should fail")
	}
	// ...and that revokes the session, so the freshly-rotated token is dead too.
	if _, err := svc.Refresh(ctx, auth.RefreshInput{RefreshToken: rotated.RefreshToken}); err == nil {
		t.Fatal("session should be revoked after reuse, rotated token must fail")
	}
}

// Hosted-login SSO session: credentials create a session, it resolves to the
// user, and revoking (hosted logout) invalidates it.
func TestHostedLoginSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	email := uniqueSlug("sso") + "@example.com"

	if _, u, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "password123"}); err != nil {
		t.Fatalf("signup: %v", err)
	} else if u.ID == uuid.Nil {
		t.Fatal("signup returned nil user id")
	}

	// Wrong password is rejected by the shared credential check.
	if _, err := svc.CheckPassword(ctx, email, "nope"); err == nil {
		t.Error("CheckPassword must reject a wrong password")
	}
	u, err := svc.CheckPassword(ctx, email, "password123")
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

	if _, _, _, err := svc.Signup(ctx, auth.SignupInput{Email: email, Password: "password123"}); err != nil {
		t.Fatalf("signup: %v", err)
	}

	// A few failures then a success must NOT lock (counter resets on success).
	for i := 0; i < 3; i++ {
		if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("wrong password should fail")
		}
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "password123"}); err != nil {
		t.Fatalf("correct password before lockout should succeed: %v", err)
	}

	// Now exhaust the threshold with consecutive failures.
	for i := 0; i < 5; i++ {
		if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "wrong"}); err == nil {
			t.Fatal("wrong password should fail")
		}
	}
	// Locked: even the correct password is refused with 429.
	_, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "password123"})
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

	code, err := svc.Authorize(ctx, userID, tenantID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("authorization_code exchange should return a refresh_token")
	}

	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken)
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
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken); err == nil {
		t.Fatal("reusing a consumed refresh token should fail")
	}
	// ...so the freshly-rotated token is dead too.
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken); err == nil {
		t.Fatal("rotated token must fail after reuse revokes the chain")
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

	code, err := svc.Authorize(ctx, userID, tenantID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "")
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
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken); err == nil {
		t.Error("a revoked refresh token must not be redeemable")
	}
	// Revoking an unknown token is still a success (RFC 7009).
	if err := svc.RevokeToken(ctx, client.ClientID, secret, "unknown-token", ""); err != nil {
		t.Errorf("revoking an unknown token should succeed: %v", err)
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
	authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), redirectURI)
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

	oneTime, err := svc.CompleteCallback(ctx, provider, state, "upstream-auth-code")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if oneTime == "" {
		t.Fatal("callback should return a one-time code")
	}

	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = 'idp-subject-123'
	`, tenantID, provider).Scan(&n); err != nil || n != 1 {
		t.Fatalf("external identity rows = %d (err %v), want 1", n, err)
	}

	pair, err := svc.ExchangeLogin(ctx, oneTime, "1.2.3.4", "test-agent")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("exchange should return access + refresh tokens")
	}

	// One-time: a second exchange of the same code must fail.
	if _, err := svc.ExchangeLogin(ctx, oneTime, "1.2.3.4", "test-agent"); err == nil {
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

// CreateWithOwner creates the tenant, an owner role granted all permissions, a
// membership row, and adopts the tenant as the creator's home.
func TestTenantCreateWithOwner(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, users := newAuth()

	_, u, _, err := svc.Signup(ctx, auth.SignupInput{Email: uniqueSlug("owner") + "@example.com", Password: "password123"})
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
