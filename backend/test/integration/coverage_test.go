//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-identity/internal/mfa"
	"github.com/qeetgroup/qeet-identity/internal/oidc"
	"github.com/qeetgroup/qeet-identity/internal/passkey"
	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/notifier"
	"github.com/qeetgroup/qeet-identity/internal/platform/tokens"
	"github.com/qeetgroup/qeet-identity/internal/platform/totp"
	"github.com/qeetgroup/qeet-identity/internal/recovery"
	"github.com/qeetgroup/qeet-identity/internal/verification"
)

// recordSender captures the last notifier message so flows that mail a code
// (verification, recovery, OTP) can be driven end-to-end in tests.
type recordSender struct{ last notifier.Message }

func (r *recordSender) Send(_ context.Context, m notifier.Message) error {
	r.last = m
	return nil
}

// codeVerifier returns an S256-compliant (verifier, challenge) pair.
func newPKCE(t *testing.T) (verifier, challenge string) {
	t.Helper()
	v, c, err := codes.URLToken() // challenge = base64url(sha256(verifier))
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	return v, c
}

// registerOIDCClient seeds a confidential client and returns it + its secret.
func registerOIDCClient(t *testing.T, ctx context.Context, svc *oidc.Service, tenantID uuid.UUID, redirectURI string) (*oidc.Client, string) {
	t.Helper()
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
	return client, secret
}

// =====================================================================
// OIDC — PKCE S256, code consumption, redirect/scope validation
// =====================================================================

// TestOIDCPKCEExchange covers the PKCE S256 verification branches of
// ExchangeCode: a correct verifier succeeds, a wrong verifier fails, a missing
// verifier (when a challenge was registered) fails, and the code is single-use.
func TestOIDCPKCEExchange(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pkce"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	// Authorize WITH a PKCE challenge (S256).
	verifier, challenge := newPKCE(t)
	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", challenge, "S256")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}

	// Wrong verifier is rejected (and per the code path the code row is left
	// for a correct retry — only a successful exchange marks it used).
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "wrong-verifier"); err == nil {
		t.Fatal("exchange with a wrong PKCE verifier must fail")
	}
	// Missing verifier when a challenge was registered is rejected.
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, ""); err == nil {
		t.Fatal("exchange with a missing PKCE verifier must fail when challenge present")
	}
	// Correct verifier succeeds.
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, verifier)
	if err != nil {
		t.Fatalf("exchange with correct verifier: %v", err)
	}
	if issued.AccessToken == "" {
		t.Fatal("exchange yielded no access token")
	}
	// Single-use: replaying the consumed code fails.
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, verifier); err == nil {
		t.Fatal("a consumed authorization code must not be redeemable again")
	}
}

// TestOIDCPKCEUnsupportedMethod proves only S256 is accepted: a code registered
// with a "plain" challenge method is rejected at exchange, even with a verifier
// that would satisfy the plain transform.
func TestOIDCPKCEUnsupportedMethod(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pkce"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	// "plain" PKCE: challenge == verifier. We still store it, but exchange must
	// refuse because the provider only supports S256.
	verifier := "plain-verifier-value"
	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", verifier, "plain")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, verifier); err == nil {
		t.Fatal("a non-S256 code_challenge_method must be rejected")
	}
}

// TestOIDCAuthorizeValidation covers Authorize's request validation: an unknown
// client, an unregistered redirect_uri, and a scope outside the client's set.
func TestOIDCAuthorizeValidation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("authz"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, _ := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	if _, _, err := svc.Authorize(ctx, userID, "qci_does-not-exist", redirectURI, []string{"openid"}, "", "", ""); err == nil {
		t.Error("authorize with an unknown client must fail")
	}
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, "https://evil.example/cb", []string{"openid"}, "", "", ""); err == nil {
		t.Error("authorize with an unregistered redirect_uri must fail")
	}
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"admin:super"}, "", "", ""); err == nil {
		t.Error("authorize with a non-permitted scope must fail")
	}
}

// TestOIDCExchangeRedirectMismatch proves the redirect_uri presented at the
// token endpoint must match the one bound to the code.
func TestOIDCExchangeRedirectMismatch(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("redir"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, "https://app.example/other", ""); err == nil {
		t.Fatal("exchange with a mismatched redirect_uri must fail")
	}
}

// TestOIDCExchangeExpiredCode forces a code's expiry into the past and proves it
// can no longer be redeemed.
func TestOIDCExchangeExpiredCode(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("exp"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_authorization_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE code_hash = $1`,
		codes.Hash(code)); err != nil {
		t.Fatalf("expire code: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, ""); err == nil {
		t.Fatal("an expired authorization code must be rejected")
	}
}

// TestOIDCRefreshClientMismatch proves a refresh token issued to one client
// cannot be redeemed by another client (token binding).
func TestOIDCRefreshClientMismatch(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("bind"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	clientA, secretA := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)
	clientB, secretB := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, clientA.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, clientA.ClientID, secretA, code, redirectURI, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("expected a refresh token")
	}
	// Client B (valid creds) trying to redeem client A's refresh token is rejected.
	if _, err := svc.RefreshToken(ctx, clientB.ClientID, secretB, issued.RefreshToken); err == nil {
		t.Fatal("a refresh token must be bound to its issuing client")
	}
	// And client A can still use it (mismatch check didn't consume it).
	if _, err := svc.RefreshToken(ctx, clientA.ClientID, secretA, issued.RefreshToken); err != nil {
		t.Fatalf("issuing client should still redeem its refresh token: %v", err)
	}
}

// TestOIDCRefreshExpired forces a stored refresh token past expiry and proves
// it can't be redeemed.
func TestOIDCRefreshExpired(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("rexp"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_refresh_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`,
		tokens.HashRefresh(issued.RefreshToken)); err != nil {
		t.Fatalf("expire refresh: %v", err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken); err == nil {
		t.Fatal("an expired refresh token must be rejected")
	}
}

// TestOIDCIntrospectClaims checks the access-token introspection payload exposes
// the issuer/audience/subject/scope the RFC 7662 consumer needs, and that the
// access_token hint short-circuits the refresh lookup.
func TestOIDCIntrospectClaims(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("intro"))
	userID := createUserInTenant(t, ctx, tenantID)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid", "profile"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	out, err := svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, "access_token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if out["active"] != true {
		t.Fatalf("access token should be active: %+v", out)
	}
	if out["iss"] != issuer.JWTIssuer() {
		t.Errorf("iss = %v, want %s", out["iss"], issuer.JWTIssuer())
	}
	if out["aud"] != issuer.JWTAudience() {
		t.Errorf("aud = %v, want %s", out["aud"], issuer.JWTAudience())
	}
	if out["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", out["token_type"])
	}
	if out["scope"] != "openid profile" {
		t.Errorf("scope = %v, want 'openid profile'", out["scope"])
	}
	if _, ok := out["exp"]; !ok {
		t.Error("introspection should include exp")
	}
}

// TestOIDCRevokeAccessTokenHintNoop proves RFC 7009 revoke with an access_token
// hint is a successful no-op (stateless JWTs can't be individually revoked).
func TestOIDCRevokeAccessTokenHintNoop(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("rev"))
	svc := oidc.NewService(testPool, mustIssuer())
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, "https://app.example/cb")

	if err := svc.RevokeToken(ctx, client.ClientID, secret, "any-access-token", "access_token"); err != nil {
		t.Errorf("revoke with access_token hint should be a no-op success: %v", err)
	}
	// Bad client auth is still rejected.
	if err := svc.RevokeToken(ctx, client.ClientID, "wrong", "tok", ""); err == nil {
		t.Error("revoke with bad client auth must fail")
	}
}

// =====================================================================
// passkey — negative ceremony / session paths (no real authenticator)
// =====================================================================

func newPasskeySvc(t *testing.T) *passkey.Service {
	t.Helper()
	authSvc, _ := newAuth()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Qeet ID", RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	return passkey.NewService(testPool, wa, authSvc)
}

// TestPasskeyFinishRegisterSessionMismatch proves FinishRegister rejects a
// session that belongs to another user (session/user binding).
func TestPasskeyFinishRegisterSessionMismatch(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pk"))
	owner := createUserInTenant(t, ctx, tenantID)
	attacker := createUserInTenant(t, ctx, tenantID)

	svc := newPasskeySvc(t)
	sid, _, err := svc.BeginRegister(ctx, owner)
	if err != nil {
		t.Fatalf("begin register: %v", err)
	}
	// A different user presenting the owner's session id is rejected.
	err = svc.FinishRegister(ctx, attacker, sid, []byte(`{}`), "")
	if err == nil {
		t.Fatal("finishing another user's registration session must fail")
	}
	if e := errs.As(err); e == nil || e.Status != 400 {
		t.Errorf("want 400 session mismatch, got %v", err)
	}
}

// TestPasskeyFinishRegisterExpiredSession forces a ceremony session past its TTL
// and proves it's refused.
func TestPasskeyFinishRegisterExpiredSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pk"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := newPasskeySvc(t)
	sid, _, err := svc.BeginRegister(ctx, userID)
	if err != nil {
		t.Fatalf("begin register: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.webauthn_sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, sid); err != nil {
		t.Fatalf("expire session: %v", err)
	}
	err = svc.FinishRegister(ctx, userID, sid, []byte(`{}`), "")
	if err == nil {
		t.Fatal("an expired ceremony session must be refused")
	}
	if e := errs.As(err); e == nil || e.Status != 400 {
		t.Errorf("want 400 expired session, got %v", err)
	}
}

// TestPasskeyFinishLoginInvalidSession proves an unknown/used session id is
// rejected, and that a session is single-use (taken on first finish).
func TestPasskeyFinishLoginSingleUse(t *testing.T) {
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
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, transports)
		VALUES ($1, $2, $3, 0, $4)
	`, userID, []byte("cred-id-x"), []byte("pub"), []string{"internal"}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	svc := newPasskeySvc(t)
	sid, _, err := svc.BeginLogin(ctx, email)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	// First finish consumes the session (fails verification — no real signature —
	// but the session is taken).
	if _, err := svc.FinishLogin(ctx, sid, []byte(`{"id":"x","rawId":"eA","type":"public-key","response":{}}`), "1.1.1.1", "ua"); err == nil {
		t.Fatal("finishing login with a bogus assertion must fail")
	}
	// Second finish with the same (now-deleted) session is an invalid-session error.
	if _, err := svc.FinishLogin(ctx, sid, []byte(`{}`), "1.1.1.1", "ua"); err == nil {
		t.Fatal("reusing a consumed ceremony session must fail")
	}
	// A wholly unknown session id is likewise rejected.
	if _, err := svc.FinishLogin(ctx, uuid.New(), []byte(`{}`), "1.1.1.1", "ua"); err == nil {
		t.Fatal("an unknown session id must fail")
	}
}

// TestPasskeyBeginLoginUnknownUser proves username-first login surfaces a clean
// not-found for an unknown email, and that a known user with no passkeys is a
// distinct bad-request (not a 500).
func TestPasskeyBeginLoginEdgeCases(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pk"))
	svc := newPasskeySvc(t)

	if _, _, err := svc.BeginLogin(ctx, "nobody-"+uniqueSlug("x")+"@example.com"); err == nil {
		t.Error("begin login for an unknown user must fail")
	}

	// A user with zero passkeys.
	email := uniqueSlug("pk") + "@example.com"
	if _, err := testPool.Exec(ctx, `INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2)`, tenantID, email); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, _, err := svc.BeginLogin(ctx, email)
	if err == nil {
		t.Fatal("begin login for a user with no passkeys must fail")
	}
	if e := errs.As(err); e == nil || e.Status != 400 {
		t.Errorf("no-passkeys should be 400, got %v", err)
	}
}

// =====================================================================
// mfa — TOTP confirm + recovery-code one-time use + email OTP lifecycle
// =====================================================================

// TestMFATOTPEnrollAndRecoveryCodes drives a real enrollment: StartEnroll mints
// a secret, ConfirmEnroll requires a valid TOTP (computed with the real
// algorithm) and returns recovery codes, and Verify consumes a recovery code
// exactly once while still accepting a fresh TOTP.
func TestMFATOTPEnrollAndRecoveryCodes(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{})

	// Start enrollment.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	enr, err := svc.StartEnroll(ctx, tx, userID, "alice@example.com")
	if err != nil {
		t.Fatalf("start enroll: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A wrong code must not confirm.
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.ConfirmEnroll(ctx, tx, userID, "000000"); err == nil {
		t.Fatal("confirm with a wrong TOTP must fail")
	}
	tx.Rollback(ctx)

	// Confirm with the real code for the current window.
	code, err := totp.Code(enr.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	tx, _ = testPool.Begin(ctx)
	recoveryCodes, err := svc.ConfirmEnroll(ctx, tx, userID, code)
	if err != nil {
		t.Fatalf("confirm enroll: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit confirm: %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(recoveryCodes))
	}

	// Verify accepts a fresh TOTP (not flagged as a recovery code).
	tx, _ = testPool.Begin(ctx)
	totpCode, _ := totp.Code(enr.Secret, time.Now().UTC())
	res, err := svc.Verify(ctx, tx, userID, totpCode)
	if err != nil {
		t.Fatalf("verify totp: %v", err)
	}
	if res.UsedRecoveryCode {
		t.Error("a TOTP verify must not be flagged as a recovery-code use")
	}
	tx.Commit(ctx)

	// Verify consumes a recovery code exactly once.
	rc := recoveryCodes[0]
	tx, _ = testPool.Begin(ctx)
	res, err = svc.Verify(ctx, tx, userID, rc)
	if err != nil {
		t.Fatalf("verify recovery code: %v", err)
	}
	if !res.UsedRecoveryCode || res.RecoveryCodeID == nil {
		t.Fatal("expected the recovery-code branch to fire")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit recovery: %v", err)
	}
	// The same recovery code can't be used a second time.
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.Verify(ctx, tx, userID, rc); err == nil {
		t.Fatal("a recovery code must be single-use")
	}
	tx.Rollback(ctx)
}

// TestMFAVerifyUnconfirmed proves Verify refuses a user whose TOTP enrollment
// was never confirmed.
func TestMFAVerifyUnconfirmed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{})

	// No enrollment at all.
	tx, _ := testPool.Begin(ctx)
	if _, err := svc.Verify(ctx, tx, userID, "123456"); err == nil {
		t.Error("verify with no MFA configured must fail")
	}
	tx.Rollback(ctx)

	// Start (but never confirm) enrollment.
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.StartEnroll(ctx, tx, userID, "a@b.c"); err != nil {
		t.Fatalf("start enroll: %v", err)
	}
	tx.Commit(ctx)
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.Verify(ctx, tx, userID, "123456"); err == nil {
		t.Error("verify before confirmation must fail")
	}
	tx.Rollback(ctx)

	// Regenerate requires a confirmed factor.
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.Regenerate(ctx, tx, userID); err == nil {
		t.Error("regenerate before confirmation must fail")
	}
	tx.Rollback(ctx)
}

// TestMFAEmailOTP exercises the email OTP factor: enroll sends a code (captured
// via the recording sender), confirm marks it verified, a fresh challenge +
// verify consumes a code, an expired code is rejected, and the destination is
// masked in the factor listing.
func TestMFAEmailOTP(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("otp"))
	userID := createUserInTenant(t, ctx, tenantID)
	rec := &recordSender{}
	svc := mfa.NewService(testPool, "qeet-test", rec)

	dest := "user@example.com"
	factorID, err := svc.EnrollOTPStart(ctx, userID, "email", dest)
	if err != nil {
		t.Fatalf("enroll otp: %v", err)
	}
	enrollCode := extractCode(t, rec.last.Body)

	// Wrong code does not confirm.
	tx, _ := testPool.Begin(ctx)
	if err := svc.EnrollOTPConfirm(ctx, tx, userID, factorID, "000000"); err == nil {
		t.Error("confirm with a wrong OTP must fail")
	}
	tx.Rollback(ctx)

	// Correct code confirms.
	tx, _ = testPool.Begin(ctx)
	if err := svc.EnrollOTPConfirm(ctx, tx, userID, factorID, enrollCode); err != nil {
		t.Fatalf("confirm otp: %v", err)
	}
	tx.Commit(ctx)

	// Channel/destination validation.
	if _, err := svc.EnrollOTPStart(ctx, userID, "carrier-pigeon", "x"); err == nil {
		t.Error("an unknown channel must be rejected")
	}
	if _, err := svc.EnrollOTPStart(ctx, userID, "email", ""); err == nil {
		t.Error("an empty destination must be rejected")
	}

	// Challenge sends a new code; verify consumes it.
	if err := svc.ChallengeOTP(ctx, userID, factorID); err != nil {
		t.Fatalf("challenge otp: %v", err)
	}
	challengeCode := extractCode(t, rec.last.Body)
	tx, _ = testPool.Begin(ctx)
	ok, err := svc.VerifyOTP(ctx, tx, userID, challengeCode)
	if err != nil || !ok {
		t.Fatalf("verify otp = %v, %v; want true", ok, err)
	}
	tx.Commit(ctx)
	// Re-using the consumed code fails.
	tx, _ = testPool.Begin(ctx)
	if ok, _ := svc.VerifyOTP(ctx, tx, userID, challengeCode); ok {
		t.Error("an OTP code must be single-use")
	}
	tx.Rollback(ctx)

	// Expired code is rejected: send one, then push it into the past.
	if err := svc.ChallengeOTP(ctx, userID, factorID); err != nil {
		t.Fatalf("challenge otp: %v", err)
	}
	staleCode := extractCode(t, rec.last.Body)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_otp_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE code_hash = $1`,
		codes.Hash(staleCode)); err != nil {
		t.Fatalf("expire code: %v", err)
	}
	tx, _ = testPool.Begin(ctx)
	if ok, _ := svc.VerifyOTP(ctx, tx, userID, staleCode); ok {
		t.Error("an expired OTP code must be rejected")
	}
	tx.Rollback(ctx)

	// Listing masks the destination.
	factors, err := svc.ListOTPFactors(ctx, userID)
	if err != nil {
		t.Fatalf("list factors: %v", err)
	}
	if len(factors) != 1 {
		t.Fatalf("expected 1 factor, got %d", len(factors))
	}
	if factors[0].Destination == dest || !strings.Contains(factors[0].Destination, "*") {
		t.Errorf("destination should be masked, got %q", factors[0].Destination)
	}
	if !factors[0].Verified {
		t.Error("factor should be marked verified")
	}
}

// =====================================================================
// recovery — password-reset lifecycle + anti-enumeration; magic links
// =====================================================================

// TestRecoveryPasswordResetLifecycle covers the full reset-token lifecycle:
// StartPasswordReset for an unknown email is a silent success (anti-enumeration,
// no row written), a real reset issues a usable token, confirming sets a new
// password and revokes sessions, and the token is single-use + expiry-checked.
func TestRecoveryPasswordResetLifecycle(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("rec"))
	email := uniqueSlug("rec") + "@example.com"
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	rec := &recordSender{}
	svc := recovery.NewService(testPool, rec, time.Hour, "https://app.qeet.com")

	// Anti-enumeration: an unknown email succeeds without sending mail or writing a row.
	rec.last = notifier.Message{}
	if err := svc.StartPasswordReset(ctx, tenantID, "ghost-"+uniqueSlug("x")+"@example.com"); err != nil {
		t.Fatalf("start reset for unknown email should succeed silently: %v", err)
	}
	if rec.last.To != "" {
		t.Error("no email should be sent for an unknown address (no enumeration signal)")
	}

	// A real reset issues a token via email.
	if err := svc.StartPasswordReset(ctx, tenantID, email); err != nil {
		t.Fatalf("start reset: %v", err)
	}
	token := extractToken(t, rec.last.Body)
	if token == "" {
		t.Fatal("reset email carried no token")
	}

	// Too-short passwords are rejected before any token lookup.
	if err := svc.ConfirmPasswordReset(ctx, token, "short", recovery.AuditCtx{}); err == nil {
		t.Error("a sub-8 password must be rejected")
	}

	// Seed a live session so we can assert it gets revoked.
	var sessionID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.sessions (user_id, tenant_id) VALUES ($1, $2) RETURNING id
	`, userID, tenantID).Scan(&sessionID); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// Confirm with the real token + a valid password.
	if err := svc.ConfirmPasswordReset(ctx, token, "new-password-123", recovery.AuditCtx{IP: "1.2.3.4"}); err != nil {
		t.Fatalf("confirm reset: %v", err)
	}
	// Sessions revoked.
	var revoked *time.Time
	if err := testPool.QueryRow(ctx, `SELECT revoked_at FROM auth.sessions WHERE id = $1`, sessionID).Scan(&revoked); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if revoked == nil {
		t.Error("password reset must revoke live sessions")
	}
	// A new credential row now exists.
	var creds int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.password_credentials WHERE user_id = $1`, userID).Scan(&creds); err != nil {
		t.Fatalf("count creds: %v", err)
	}
	if creds != 1 {
		t.Errorf("expected 1 password credential, got %d", creds)
	}
	// Single-use: the token can't be replayed.
	if err := svc.ConfirmPasswordReset(ctx, token, "another-password-1", recovery.AuditCtx{}); err == nil {
		t.Error("a used reset token must not be redeemable again")
	}
	// An unknown token is rejected.
	if err := svc.ConfirmPasswordReset(ctx, "not-a-real-token", "another-password-1", recovery.AuditCtx{}); err == nil {
		t.Error("an unknown reset token must be rejected")
	}
}

// TestRecoveryResetTokenExpiry forces a reset token past its TTL and proves it's
// refused.
func TestRecoveryResetTokenExpiry(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("rec"))
	email := uniqueSlug("rec") + "@example.com"
	if _, err := testPool.Exec(ctx, `INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2)`, tenantID, email); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rec := &recordSender{}
	svc := recovery.NewService(testPool, rec, time.Hour, "https://app.qeet.com")
	if err := svc.StartPasswordReset(ctx, tenantID, email); err != nil {
		t.Fatalf("start reset: %v", err)
	}
	token := extractToken(t, rec.last.Body)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.password_resets SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`,
		codes.Hash(token)); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, token, "new-password-123", recovery.AuditCtx{}); err == nil {
		t.Error("an expired reset token must be rejected")
	}
}

// TestRecoveryMagicLink covers the magic-link lifecycle: consume resolves the
// (user, tenant), a used link can't be replayed, and an expired one is refused.
func TestRecoveryMagicLink(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("magic"))
	email := uniqueSlug("magic") + "@example.com"
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rec := &recordSender{}
	svc := recovery.NewService(testPool, rec, time.Hour, "https://app.qeet.com")

	if err := svc.StartMagicLink(ctx, tenantID, email); err != nil {
		t.Fatalf("start magic link: %v", err)
	}
	token := extractToken(t, rec.last.Body)

	res, err := svc.ConsumeMagicLink(ctx, token, recovery.AuditCtx{})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if res.UserID != userID || res.TenantID != tenantID {
		t.Errorf("consume = %v/%v, want %v/%v", res.UserID, res.TenantID, userID, tenantID)
	}
	// Single-use.
	if _, err := svc.ConsumeMagicLink(ctx, token, recovery.AuditCtx{}); err == nil {
		t.Error("a consumed magic link must not be reusable")
	}

	// Expiry path.
	if err := svc.StartMagicLink(ctx, tenantID, email); err != nil {
		t.Fatalf("start magic link 2: %v", err)
	}
	token2 := extractToken(t, rec.last.Body)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.magic_links SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`,
		codes.Hash(token2)); err != nil {
		t.Fatalf("expire link: %v", err)
	}
	if _, err := svc.ConsumeMagicLink(ctx, token2, recovery.AuditCtx{}); err == nil {
		t.Error("an expired magic link must be refused")
	}

	// Unknown token.
	if _, err := svc.ConsumeMagicLink(ctx, "nope", recovery.AuditCtx{}); err == nil {
		t.Error("an unknown magic-link token must be refused")
	}
}

// =====================================================================
// verification — email code issue / confirm / reuse / expiry
// =====================================================================

// TestVerificationEmailLifecycle drives the email-verification flow: a code is
// issued (captured via the recording sender), the wrong code fails, the right
// code marks the email verified, and the code is single-use + expiry-checked.
func TestVerificationEmailLifecycle(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("ver"))
	email := uniqueSlug("ver") + "@example.com"
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rec := &recordSender{}
	svc := verification.NewService(testPool, rec, 10*time.Minute)

	if err := svc.StartEmail(ctx, userID, email); err != nil {
		t.Fatalf("start email: %v", err)
	}
	code := extractCode(t, rec.last.Body)

	// Wrong code is rejected.
	if err := svc.ConfirmEmail(ctx, userID, "000000"); err == nil {
		t.Error("a wrong verification code must be rejected")
	}
	// Correct code verifies and stamps email_verified_at.
	if err := svc.ConfirmEmail(ctx, userID, code); err != nil {
		t.Fatalf("confirm email: %v", err)
	}
	var verifiedAt *time.Time
	if err := testPool.QueryRow(ctx, `SELECT email_verified_at FROM "user".users WHERE id = $1`, userID).Scan(&verifiedAt); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if verifiedAt == nil {
		t.Error("email_verified_at should be set after confirmation")
	}
	// Single-use.
	if err := svc.ConfirmEmail(ctx, userID, code); err == nil {
		t.Error("a used verification code must not be reusable")
	}

	// Expiry path.
	if err := svc.StartEmail(ctx, userID, email); err != nil {
		t.Fatalf("start email 2: %v", err)
	}
	code2 := extractCode(t, rec.last.Body)
	if _, err := testPool.Exec(ctx,
		`UPDATE "user".email_verifications SET expires_at = NOW() - INTERVAL '1 minute' WHERE code_hash = $1`,
		codes.Hash(code2)); err != nil {
		t.Fatalf("expire code: %v", err)
	}
	if err := svc.ConfirmEmail(ctx, userID, code2); err == nil {
		t.Error("an expired verification code must be rejected")
	}
}

// TestVerificationPhoneLifecycle mirrors the email flow for phone codes.
func TestVerificationPhoneLifecycle(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("ver"))
	phone := "+1555555" + uniqueSlug("0")[:4]
	var userID uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (tenant_id, email) VALUES ($1, $2) RETURNING id`, tenantID, uniqueSlug("ph")+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	rec := &recordSender{}
	svc := verification.NewService(testPool, rec, 10*time.Minute)

	if err := svc.StartPhone(ctx, userID, phone); err != nil {
		t.Fatalf("start phone: %v", err)
	}
	code := extractCode(t, rec.last.Body)
	if err := svc.ConfirmPhone(ctx, userID, "000000"); err == nil {
		t.Error("a wrong phone code must be rejected")
	}
	if err := svc.ConfirmPhone(ctx, userID, code); err != nil {
		t.Fatalf("confirm phone: %v", err)
	}
	var verifiedAt *time.Time
	if err := testPool.QueryRow(ctx, `SELECT phone_verified_at FROM "user".users WHERE id = $1`, userID).Scan(&verifiedAt); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if verifiedAt == nil {
		t.Error("phone_verified_at should be set after confirmation")
	}
}

// =====================================================================
// helpers
// =====================================================================

// extractCode pulls a 6-digit numeric code out of a notification body.
func extractCode(t *testing.T, body string) string {
	t.Helper()
	for _, f := range strings.FieldsFunc(body, func(r rune) bool { return r < '0' || r > '9' }) {
		if len(f) == 6 {
			return f
		}
	}
	t.Fatalf("no 6-digit code in body: %q", body)
	return ""
}

// extractToken pulls the URL-safe token out of a reset/magic-link body of the
// form "...?token=<raw>".
func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = "token="
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no token in body: %q", body)
	}
	tok := body[i+len(marker):]
	if j := strings.IndexAny(tok, " \n\t"); j >= 0 {
		tok = tok[:j]
	}
	return tok
}
