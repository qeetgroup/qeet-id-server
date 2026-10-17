//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/mfa"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/identity/verification"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption/totp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
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

func registerOIDCPublicClient(t *testing.T, ctx context.Context, svc *oidc.Service, tenantID uuid.UUID, redirectURI string) *oidc.Client {
	t.Helper()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Type: "public", Name: "Public RP",
		RedirectURIs: []string{redirectURI}, GrantTypes: []string{"authorization_code", "refresh_token"},
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("register public client: %v", err)
	}
	if secret != "" {
		_ = tx.Rollback(ctx)
		t.Fatal("public client must not receive a secret")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return client
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
	addTenantMembership(t, ctx, userID, tenantID)

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
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "wrong-verifier", ""); err == nil {
		t.Fatal("exchange with a wrong PKCE verifier must fail")
	}
	// Missing verifier when a challenge was registered is rejected.
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", ""); err == nil {
		t.Fatal("exchange with a missing PKCE verifier must fail when challenge present")
	}
	// Correct verifier succeeds.
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, verifier, "")
	if err != nil {
		t.Fatalf("exchange with correct verifier: %v", err)
	}
	if issued.AccessToken == "" {
		t.Fatal("exchange yielded no access token")
	}
	// Single-use: replaying the consumed code fails.
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, verifier, ""); err == nil {
		t.Fatal("a consumed authorization code must not be redeemable again")
	}
}

// TestOIDCPKCEUnsupportedMethod proves only S256 is accepted and invalid
// challenges are rejected before an authorization code is issued.
func TestOIDCPKCEUnsupportedMethod(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("pkce"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	verifier := "plain-verifier-value"
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", verifier, "plain"); !errors.Is(err, errs.ErrOIDCCodeChallengeMethodUnsupported) {
		t.Fatalf("plain PKCE error = %v, want unsupported method", err)
	}
	_ = secret
}

func TestOIDCPublicClientRequiresStrictPKCE(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("public-pkce"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)
	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://public.example/cb"
	client := registerOIDCPublicClient(t, ctx, svc, tenantID, redirectURI)

	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
		t.Fatalf("missing public-client challenge error = %v", err)
	}
	verifier, challenge := newPKCE(t)
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", challenge, ""); !errors.Is(err, errs.ErrOIDCCodeChallengeMethodUnsupported) {
		t.Fatalf("missing PKCE method error = %v", err)
	}
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", strings.Repeat("a", 42), "S256"); !errors.Is(err, errs.ErrOIDCCodeChallengeInvalid) {
		t.Fatalf("short PKCE challenge error = %v", err)
	}
	if _, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", strings.Repeat("a", 42)+"!", "S256"); !errors.Is(err, errs.ErrOIDCCodeChallengeInvalid) {
		t.Fatalf("malformed PKCE challenge error = %v", err)
	}

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", challenge, "S256")
	if err != nil {
		t.Fatalf("authorize public client with S256: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, "", code, redirectURI, "too-short", ""); !errors.Is(err, errs.ErrOIDCCodeVerifierInvalid) {
		t.Fatalf("malformed verifier error = %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, "", code, redirectURI, strings.Repeat("a", 42)+"!", ""); !errors.Is(err, errs.ErrOIDCCodeVerifierInvalid) {
		t.Fatalf("illegal-character verifier error = %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, "", code, redirectURI, verifier, "")
	if err != nil {
		t.Fatalf("exchange public-client code with S256: %v", err)
	}
	if issued.AccessToken == "" {
		t.Fatal("public-client S256 exchange returned no access token")
	}

	legacyCode, legacyHash, err := codes.URLToken()
	if err != nil {
		t.Fatalf("legacy authorization code: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.oidc_authorization_codes
		    (code_hash, client_id, user_id, tenant_id, redirect_uri, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, ARRAY['openid']::text[], NOW() + INTERVAL '5 minutes')
	`, legacyHash, client.ClientID, userID, tenantID, redirectURI); err != nil {
		t.Fatalf("seed challenge-less public code: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, "", legacyCode, redirectURI, verifier, ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
		t.Fatalf("challenge-less public code error = %v", err)
	}
}

// TestOIDCAuthorizeValidation covers Authorize's request validation: an unknown
// client, an unregistered redirect_uri, and a scope outside the client's set.
func TestOIDCAuthorizeValidation(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("authz"))
	userID := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, userID, tenantID)

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
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, "https://app.example/other", "", ""); err == nil {
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
	addTenantMembership(t, ctx, userID, tenantID)

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
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", ""); err == nil {
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
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	clientA, secretA := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)
	clientB, secretB := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, clientA.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, clientA.ClientID, secretA, code, redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("expected a refresh token")
	}
	// Client B (valid creds) trying to redeem client A's refresh token is rejected.
	if _, err := svc.RefreshToken(ctx, clientB.ClientID, secretB, issued.RefreshToken, ""); err == nil {
		t.Fatal("a refresh token must be bound to its issuing client")
	}
	// And client A can still use it (mismatch check didn't consume it).
	if _, err := svc.RefreshToken(ctx, clientA.ClientID, secretA, issued.RefreshToken, ""); err != nil {
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
	addTenantMembership(t, ctx, userID, tenantID)

	svc := oidc.NewService(testPool, mustIssuer())
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.oidc_refresh_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE token_hash = $1`,
		tokens.HashRefresh(issued.RefreshToken)); err != nil {
		t.Fatalf("expire refresh: %v", err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
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
	addTenantMembership(t, ctx, userID, tenantID)

	issuer := mustIssuer()
	svc := oidc.NewService(testPool, issuer)
	redirectURI := "https://app.example/cb"
	client, secret := registerOIDCClient(t, ctx, svc, tenantID, redirectURI)

	code, _, err := svc.Authorize(ctx, userID, client.ClientID, redirectURI, []string{"openid", "profile"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirectURI, "", "")
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
	return newPasskeySvcWithAuth(t, authSvc)
}

// newPasskeySvcWithAuth builds the passkey service on a given auth service, for
// tests that need extra auth wiring (for example a registration policy).
func newPasskeySvcWithAuth(t *testing.T, authSvc *auth.Service) *passkey.Service {
	t.Helper()
	// Mirror the production config in internal/bootstrap/dependencies.go —
	// crucially AuthenticatorSelection.UserVerification, which is what gates
	// go-webauthn's UV check. A test config that omits it silently verifies
	// weaker assertions than production does.
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "localhost", RPDisplayName: "Qeet ID", RPOrigins: []string{"http://localhost:3000"},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		},
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
	err = svc.FinishRegister(ctx, attacker, sid, []byte(`{}`), "", "")
	if err == nil {
		t.Fatal("finishing another user's registration session must fail")
	}
	if e := errs.As(err); e == nil || e.Code != errs.ErrPasskeySessionMismatch.Code {
		t.Errorf("want passkey session mismatch, got %v", err)
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
	err = svc.FinishRegister(ctx, userID, sid, []byte(`{}`), "", "")
	if err == nil {
		t.Fatal("an expired ceremony session must be refused")
	}
	if e := errs.As(err); e == nil || e.Code != errs.ErrAuthSessionExpired.Code {
		t.Errorf("want expired session, got %v", err)
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
	if e := errs.As(err); e == nil || e.Code != errs.ErrPasskeyNoCredentials.Code {
		t.Errorf("want no-credentials error, got %v", err)
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
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))

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
	var storedSecret string
	var secretCiphertext, secretNonce []byte
	if err := testPool.QueryRow(ctx, `
		SELECT secret, secret_ct, secret_nonce FROM auth.mfa_totp WHERE user_id = $1
	`, userID).Scan(&storedSecret, &secretCiphertext, &secretNonce); err != nil {
		t.Fatalf("read stored TOTP: %v", err)
	}
	if storedSecret != "" || len(secretCiphertext) == 0 || len(secretNonce) == 0 {
		t.Fatalf("TOTP must be ciphertext-only: plaintext=%q ciphertext=%d nonce=%d", storedSecret, len(secretCiphertext), len(secretNonce))
	}
	if bytes.Contains(secretCiphertext, []byte(enr.Secret)) {
		t.Fatal("TOTP ciphertext must not contain the plaintext secret")
	}

	// A wrong code must not confirm.
	if _, err := mfaConfirmEnroll(ctx, svc, userID, "000000"); err == nil {
		t.Fatal("confirm with a wrong TOTP must fail")
	}

	// Confirm with the real code for the current window.
	code, err := totp.Code(enr.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	recoveryCodes, err := mfaConfirmEnroll(ctx, svc, userID, code)
	if err != nil {
		t.Fatalf("confirm enroll: %v", err)
	}
	if len(recoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(recoveryCodes))
	}

	// Verify accepts a fresh TOTP (not flagged as a recovery code). Step +1:
	// the enrollment code above consumed the current step, and a consumed step
	// is now rejected as a replay.
	totpCode := totpCodeAtStep(t, enr.Secret, 1)
	res, err := mfaVerify(ctx, svc, userID, totpCode)
	if err != nil {
		t.Fatalf("verify totp: %v", err)
	}
	if res.UsedRecoveryCode {
		t.Error("a TOTP verify must not be flagged as a recovery-code use")
	}

	// Verify consumes a recovery code exactly once.
	rc := recoveryCodes[0]
	res, err = mfaVerify(ctx, svc, userID, rc)
	if err != nil {
		t.Fatalf("verify recovery code: %v", err)
	}
	if !res.UsedRecoveryCode || res.RecoveryCodeID == nil {
		t.Fatal("expected the recovery-code branch to fire")
	}
	// The same recovery code can't be used a second time.
	if _, err := mfaVerify(ctx, svc, userID, rc); err == nil {
		t.Fatal("a recovery code must be single-use")
	}

	legacyUserID := createUserInTenant(t, ctx, tenantID)
	legacySecret, err := totp.NewSecret()
	if err != nil {
		t.Fatalf("legacy TOTP secret: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.mfa_totp (user_id, secret) VALUES ($1, $2)
	`, legacyUserID, legacySecret); err != nil {
		t.Fatalf("seed legacy TOTP: %v", err)
	}
	legacyCode, err := totp.Code(legacySecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("legacy TOTP code: %v", err)
	}
	if _, err := mfaConfirmEnroll(ctx, svc, legacyUserID, legacyCode); err != nil {
		t.Fatalf("confirm legacy TOTP: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		SELECT secret, secret_ct, secret_nonce FROM auth.mfa_totp WHERE user_id = $1
	`, legacyUserID).Scan(&storedSecret, &secretCiphertext, &secretNonce); err != nil {
		t.Fatalf("read migrated TOTP: %v", err)
	}
	if storedSecret != "" || len(secretCiphertext) == 0 || len(secretNonce) == 0 {
		t.Fatal("legacy TOTP seed was not migrated to ciphertext-only storage")
	}
}

func TestMFAFactorAndOTPAttemptBudgets(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-budget"))
	userID := createUserInTenant(t, ctx, tenantID)
	recorder := &recordSender{}
	service := mfa.NewService(testPool, "qeet-test", recorder, "")
	service.SetCipher(testEnvelope(t))

	tx, _ := testPool.Begin(ctx)
	enrollment, err := service.StartEnroll(ctx, tx, userID, "budget@example.com")
	if err != nil {
		t.Fatalf("start TOTP enrollment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit TOTP enrollment: %v", err)
	}
	totpCode, _ := totp.Code(enrollment.Secret, time.Now().UTC())
	if _, err := mfaConfirmEnroll(ctx, service, userID, totpCode); err != nil {
		t.Fatalf("confirm TOTP enrollment: %v", err)
	}

	for attempt := 1; attempt <= 5; attempt++ {
		_, verifyErr := mfaVerify(ctx, service, userID, "not-a-code")
		if attempt < 5 && !errors.Is(verifyErr, errs.ErrMFACodeInvalid) {
			t.Fatalf("factor attempt %d error = %v", attempt, verifyErr)
		}
		if attempt == 5 && !errors.Is(verifyErr, errs.ErrMFAAttemptsExceeded) {
			t.Fatalf("fifth factor attempt error = %v, want exhausted", verifyErr)
		}
	}
	if _, err := mfaVerify(ctx, service, userID, totpCode); !errors.Is(err, errs.ErrMFAAttemptsExceeded) {
		t.Fatalf("correct TOTP after exhaustion error = %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		UPDATE auth.mfa_attempt_budgets
		SET locked_until = NOW() - INTERVAL '1 second', window_started_at = NOW() - INTERVAL '11 minutes'
		WHERE user_id = $1 AND purpose = 'factor-verify'
	`, userID); err != nil {
		t.Fatalf("expire factor budget: %v", err)
	}
	// Step +1: the enrollment confirm above consumed the current step, and the
	// exhausted-budget attempts were rejected before reaching TOTP verification,
	// so they consumed nothing.
	if _, err := mfaVerify(ctx, service, userID, totpCodeAtStep(t, enrollment.Secret, 1)); err != nil {
		t.Fatalf("correct TOTP after lockout expiry: %v", err)
	}

	factorID, err := service.EnrollOTPStart(ctx, userID, nil, "email", "budget@example.com")
	if err != nil {
		t.Fatalf("start email OTP enrollment: %v", err)
	}
	enrollmentCode := extractCode(t, recorder.last.Body)
	if err := mfaEnrollOTPConfirm(ctx, service, userID, factorID, enrollmentCode); err != nil {
		t.Fatalf("confirm email OTP: %v", err)
	}
	allowNextCode(t, ctx, factorID)
	if err := service.ChallengeOTP(ctx, userID, nil, factorID); err != nil {
		t.Fatalf("challenge email OTP: %v", err)
	}
	challengeCode := extractCode(t, recorder.last.Body)
	for attempt := 1; attempt <= 5; attempt++ {
		_, verifyErr := mfaVerifyOTP(ctx, service, userID, "000000")
		if attempt == 5 && !errors.Is(verifyErr, errs.ErrMFAAttemptsExceeded) {
			t.Fatalf("fifth OTP attempt error = %v, want exhausted", verifyErr)
		}
	}
	if _, err := mfaVerifyOTP(ctx, service, userID, challengeCode); !errors.Is(err, errs.ErrMFAAttemptsExceeded) {
		t.Fatalf("correct OTP after exhaustion error = %v", err)
	}
}

func TestMFARecoveryCodeConcurrentSingleUse(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-recovery-race"))
	userID := createUserInTenant(t, ctx, tenantID)
	service := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	service.SetCipher(testEnvelope(t))
	tx, _ := testPool.Begin(ctx)
	enrollment, err := service.StartEnroll(ctx, tx, userID, "race@example.com")
	if err != nil {
		t.Fatalf("start enrollment: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enrollment: %v", err)
	}
	code, _ := totp.Code(enrollment.Secret, time.Now().UTC())
	recoveryCodes, err := mfaConfirmEnroll(ctx, service, userID, code)
	if err != nil {
		t.Fatalf("confirm enrollment: %v", err)
	}

	const contenders = 8
	start := make(chan struct{})
	results := make(chan bool, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			attempt, err := service.ReserveAttempt(ctx, userID, mfa.PurposeFactorVerify)
			if err != nil {
				results <- false
				return
			}
			tx, err := testPool.Begin(ctx)
			if err != nil {
				results <- false
				return
			}
			result, err := service.Verify(ctx, tx, attempt, recoveryCodes[0])
			if err != nil || result == nil || !result.UsedRecoveryCode {
				_ = tx.Rollback(ctx)
				results <- false
				return
			}
			if err := tx.Commit(ctx); err != nil {
				results <- false
				return
			}
			results <- true
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
		t.Fatalf("concurrent recovery-code successes = %d, want 1", successes)
	}
}

// TestMFAVerifyUnconfirmed proves Verify refuses a user whose TOTP enrollment
// was never confirmed.
func TestMFAVerifyUnconfirmed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))

	// No enrollment at all.
	if _, err := mfaVerify(ctx, svc, userID, "123456"); err == nil {
		t.Error("verify with no MFA configured must fail")
	}

	// Start (but never confirm) enrollment.
	tx, _ := testPool.Begin(ctx)
	if _, err := svc.StartEnroll(ctx, tx, userID, "a@b.c"); err != nil {
		t.Fatalf("start enroll: %v", err)
	}
	tx.Commit(ctx)
	if _, err := mfaVerify(ctx, svc, userID, "123456"); err == nil {
		t.Error("verify before confirmation must fail")
	}

	// Regenerate requires a confirmed factor.
	tx, _ = testPool.Begin(ctx)
	if _, err := svc.Regenerate(ctx, tx, userID); err == nil {
		t.Error("regenerate before confirmation must fail")
	}
	tx.Rollback(ctx)
}

func TestMFAPushSecretsEncryptedAndMigrated(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfa-push"))
	userID := createUserInTenant(t, ctx, tenantID)
	svc := mfa.NewService(testPool, "qeet-test", notifier.LogSender{}, "")
	svc.SetCipher(testEnvelope(t))

	device, firstCredential, err := svc.RegisterPushDevice(ctx, userID, "phone", "ExponentPushToken[new-device]", "ios")
	if err != nil {
		t.Fatalf("register push device: %v", err)
	}
	var pushPlaintext, devicePlaintext *string
	var ciphertext, nonce []byte
	var pushHash, deviceHash *string
	if err := testPool.QueryRow(ctx, `
		SELECT push_token, device_token, push_token_ct, push_token_nonce,
		       push_token_hash, device_token_hash
		FROM auth.mfa_push_devices WHERE id = $1
	`, device.ID).Scan(&pushPlaintext, &devicePlaintext, &ciphertext, &nonce, &pushHash, &deviceHash); err != nil {
		t.Fatalf("read stored push device: %v", err)
	}
	if pushPlaintext != nil || devicePlaintext != nil || len(ciphertext) == 0 || len(nonce) == 0 || pushHash == nil || deviceHash == nil {
		t.Fatalf("push credentials must use ciphertext/hash storage: push=%v device=%v ciphertext=%d nonce=%d", pushPlaintext, devicePlaintext, len(ciphertext), len(nonce))
	}

	rotated, secondCredential, err := svc.RegisterPushDevice(ctx, userID, "phone updated", "ExponentPushToken[new-device]", "ios")
	if err != nil {
		t.Fatalf("rotate push device credential: %v", err)
	}
	if rotated.ID != device.ID || secondCredential == firstCredential {
		t.Fatalf("re-registration must retain device and rotate credential: first=%s second=%s", device.ID, rotated.ID)
	}
	challengeID, err := svc.CreatePushChallenge(ctx, userID, "login", mfa.PushChallengeContext{Timestamp: time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		t.Fatalf("create push challenge: %v", err)
	}
	if err := svc.RespondToPushChallenge(ctx, challengeID, userID, firstCredential, true); err == nil {
		t.Fatal("rotated device credential must no longer authorize a response")
	}
	if err := svc.RespondToPushChallenge(ctx, challengeID, userID, secondCredential, true); err != nil {
		t.Fatalf("current device credential should authorize response: %v", err)
	}

	legacyPush := "ExponentPushToken[legacy-device]"
	legacyCredential := "legacy-device-credential"
	var legacyID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.mfa_push_devices (user_id, name, push_token, platform, device_token)
		VALUES ($1, 'legacy phone', $2, 'android', $3)
		RETURNING id
	`, userID, legacyPush, legacyCredential).Scan(&legacyID); err != nil {
		t.Fatalf("seed legacy push device: %v", err)
	}
	if _, err := svc.CreatePushChallenge(ctx, userID, "legacy-login", mfa.PushChallengeContext{Timestamp: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("migrate legacy push device: %v", err)
	}
	if err := testPool.QueryRow(ctx, `
		SELECT push_token, device_token, push_token_ct, push_token_nonce,
		       push_token_hash, device_token_hash
		FROM auth.mfa_push_devices WHERE id = $1
	`, legacyID).Scan(&pushPlaintext, &devicePlaintext, &ciphertext, &nonce, &pushHash, &deviceHash); err != nil {
		t.Fatalf("read migrated push device: %v", err)
	}
	if pushPlaintext != nil || devicePlaintext != nil || len(ciphertext) == 0 || len(nonce) == 0 || pushHash == nil || deviceHash == nil {
		t.Fatal("legacy push credentials were not migrated to ciphertext/hash storage")
	}
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
	svc := mfa.NewService(testPool, "qeet-test", rec, "")
	svc.SetCipher(testEnvelope(t))

	dest := "user@example.com"
	factorID, err := svc.EnrollOTPStart(ctx, userID, nil, "email", dest)
	if err != nil {
		t.Fatalf("enroll otp: %v", err)
	}
	enrollCode := extractCode(t, rec.last.Body)

	// Wrong code does not confirm.
	if err := mfaEnrollOTPConfirm(ctx, svc, userID, factorID, "000000"); err == nil {
		t.Error("confirm with a wrong OTP must fail")
	}

	// Correct code confirms.
	if err := mfaEnrollOTPConfirm(ctx, svc, userID, factorID, enrollCode); err != nil {
		t.Fatalf("confirm otp: %v", err)
	}

	// Channel/destination validation.
	if _, err := svc.EnrollOTPStart(ctx, userID, nil, "carrier-pigeon", "x"); err == nil {
		t.Error("an unknown channel must be rejected")
	}
	if _, err := svc.EnrollOTPStart(ctx, userID, nil, "email", ""); err == nil {
		t.Error("an empty destination must be rejected")
	}

	// Challenge sends a new code; verify consumes it.
	allowNextCode(t, ctx, factorID)
	if err := svc.ChallengeOTP(ctx, userID, nil, factorID); err != nil {
		t.Fatalf("challenge otp: %v", err)
	}
	challengeCode := extractCode(t, rec.last.Body)
	ok, err := mfaVerifyOTP(ctx, svc, userID, challengeCode)
	if err != nil || !ok {
		t.Fatalf("verify otp = %v, %v; want true", ok, err)
	}
	// Re-using the consumed code fails.
	if ok, _ := mfaVerifyOTP(ctx, svc, userID, challengeCode); ok {
		t.Error("an OTP code must be single-use")
	}

	// Expired code is rejected: send one, then push it into the past.
	allowNextCode(t, ctx, factorID)
	if err := svc.ChallengeOTP(ctx, userID, nil, factorID); err != nil {
		t.Fatalf("challenge otp: %v", err)
	}
	staleCode := extractCode(t, rec.last.Body)
	if _, err := testPool.Exec(ctx,
		`UPDATE auth.mfa_otp_codes SET expires_at = NOW() - INTERVAL '1 minute' WHERE code_hash = $1`,
		codes.Hash(staleCode)); err != nil {
		t.Fatalf("expire code: %v", err)
	}
	if ok, _ := mfaVerifyOTP(ctx, svc, userID, staleCode); ok {
		t.Error("an expired OTP code must be rejected")
	}

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
// mfa — WebAuthn second factor (reusing existing passkey credentials)
// =====================================================================

// TestMFAWebAuthnBeginNoCredentials proves BeginMFA refuses a user who has no
// registered passkeys — a security key can only serve as a second factor if one
// is enrolled.
func TestMFAWebAuthnBeginNoCredentials(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfawa"))
	userID := createUserInTenant(t, ctx, tenantID)

	svc := newPasskeySvc(t)
	if _, _, err := svc.BeginMFA(ctx, userID); err == nil {
		t.Fatal("BeginMFA for a user with no passkeys must fail")
	} else if e := errs.As(err); e == nil || e.Code != errs.ErrPasskeyNoCredentials.Code {
		t.Errorf("want no-credentials error, got %v", err)
	}
}

// TestMFAWebAuthnFinishRejectsMismatch proves FinishMFA enforces user-isolation
// (a session bound to one user can't be finished by another) and flow-isolation
// (a non-"mfa" session — here a login session — can't be replayed as a second
// factor).
func TestMFAWebAuthnFinishRejectsMismatch(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("mfawa"))
	owner := createUserInTenant(t, ctx, tenantID)
	attacker := createUserInTenant(t, ctx, tenantID)

	// Owner gets a passkey so BeginMFA can start a real ceremony.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.passkey_credentials (user_id, credential_id, public_key, sign_count, transports)
		VALUES ($1, $2, $3, 0, $4)
	`, owner, []byte("mfa-cred-"+uniqueSlug("c")), []byte("pub"), []string{"internal"}); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	svc := newPasskeySvc(t)
	sid, _, err := svc.BeginMFA(ctx, owner)
	if err != nil {
		t.Fatalf("begin mfa: %v", err)
	}
	// Another user presenting the owner's mfa session is rejected (user binding).
	if err := svc.FinishMFA(ctx, attacker, sid, []byte(`{}`)); err == nil {
		t.Fatal("finishing another user's mfa session must fail")
	} else if e := errs.As(err); e == nil || e.Code != errs.ErrPasskeySessionMismatch.Code {
		t.Errorf("want passkey session mismatch, got %v", err)
	}

	// A non-mfa ("login") session can't be used to finish an mfa ceremony, even
	// by the right user (flow binding via the kind column).
	var loginSID uuid.UUID
	if err := testPool.QueryRow(ctx, `
		INSERT INTO auth.webauthn_sessions (user_id, kind, data, expires_at)
		VALUES ($1, 'login', '{}'::jsonb, NOW() + INTERVAL '5 minutes') RETURNING id
	`, owner).Scan(&loginSID); err != nil {
		t.Fatalf("seed login session: %v", err)
	}
	if err := svc.FinishMFA(ctx, owner, loginSID, []byte(`{}`)); err == nil {
		t.Fatal("a login-kind session must not satisfy an mfa finish")
	} else if e := errs.As(err); e == nil || e.Code != errs.ErrPasskeySessionMismatch.Code {
		t.Errorf("want passkey session mismatch (wrong kind), got %v", err)
	}
}

// withPrincipal injects an authenticated user principal, standing in for the
// RequireAuth middleware the real router runs ahead of d.MFA.Mount.
func withPrincipal(userID, tenantID uuid.UUID) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid, tid := userID, tenantID
			p := &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: "user", Subject: uid.String()}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
		})
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
	svc.SetPasswordRules(authpolicy.NewService(testPool))

	// Anti-enumeration: an unknown email succeeds without sending mail or writing a row.
	rec.last = notifier.Message{}
	if _, err := svc.StartPasswordReset(ctx, "ghost-"+uniqueSlug("x")+"@example.com"); err != nil {
		t.Fatalf("start reset for unknown email should succeed silently: %v", err)
	}
	if rec.last.To != "" {
		t.Error("no email should be sent for an unknown address (no enumeration signal)")
	}

	// A real reset issues a token via email.
	if _, err := svc.StartPasswordReset(ctx, email); err != nil {
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
	svc.SetPasswordRules(authpolicy.NewService(testPool))
	if _, err := svc.StartPasswordReset(ctx, email); err != nil {
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
