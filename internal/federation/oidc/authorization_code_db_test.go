//go:build integration

package oidc

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestCodeRedemptionRefusedAfterRemoval checks that an authorization code is
// re-judged when it is redeemed: once its person has left the application's
// organization, or the application no longer has the authorization_code
// grant, it buys no token, and it is spent.
func TestCodeRedemptionRefusedAfterRemoval(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	client, secret := registerClient(t, svc, organization)
	code := func(userID uuid.UUID) (string, string) {
		t.Helper()
		verifier, challenge, err := codes.URLToken()
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := svc.Authorize(ctx, userID, client.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		return c, verifier
	}

	leaver := dbtest.User(t, dbtest.Organization(t), organization)
	c, verifier := code(leaver.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, leaver.ID, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, c, testRedirect, verifier, ""); !errors.Is(err, ErrUserOrganizationMismatch) {
		t.Errorf("redeem the code of someone removed since: %v, want %v", err, ErrUserOrganizationMismatch)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_authorization_codes WHERE code_hash = $1 AND used_at IS NOT NULL`, codes.Hash(c)); n != 1 {
		t.Error("the refused code was not spent")
	}

	member := dbtest.User(t, organization, organization)
	c, verifier = code(member.ID)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.oidc_clients SET grant_types = '{refresh_token}' WHERE client_id = $1`, client.ClientID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, c, testRedirect, verifier, ""); !errors.Is(err, ErrGrantTypeNotAllowed) {
		t.Errorf("redeem a code after the application lost the authorization_code grant: %v, want %v", err, ErrGrantTypeNotAllowed)
	}
}

// TestCodeRedemptionRules checks that a code redeems only for the application
// it was issued to, at its redirect_uri, before it expires and while the
// account is active, and that a PKCE exemption waives the proof key only for
// a confidential application and only while it lasts.
func TestCodeRedemptionRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	sibling, siblingSecret := registerClient(t, svc, organization)
	public, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public"})
	authorize := func(clientID string) (string, string) {
		t.Helper()
		verifier, challenge, _ := codes.URLToken()
		code, _, err := svc.Authorize(ctx, person.ID, clientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		return code, verifier
	}

	code, verifier := authorize(client.ClientID)
	if _, err := svc.ExchangeCode(ctx, sibling.ClientID, siblingSecret, code, testRedirect, verifier, ""); !errors.Is(err, ErrAuthCodeInvalid) {
		t.Errorf("redeem by another application: %v, want %v", err, ErrAuthCodeInvalid)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect+"/other", verifier, ""); !errors.Is(err, ErrRedirectURIMismatch) {
		t.Errorf("redeem at another redirect_uri: %v, want %v", err, ErrRedirectURIMismatch)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); err != nil {
		t.Errorf("redeem after the refused attempts: %v", err)
	}

	code, verifier = authorize(client.ClientID)
	if _, err := pool.Exec(ctx, `UPDATE auth.oidc_authorization_codes SET expires_at = NOW() - INTERVAL '1 second'
		WHERE organization_id = $1 AND code_hash = $2`, organization, codes.Hash(code)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, ErrAuthCodeExpired) {
		t.Errorf("redeem an expired code: %v, want %v", err, ErrAuthCodeExpired)
	}

	code, verifier = authorize(client.ClientID)
	setStatus := func(status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE account.users SET status = $2 WHERE organization_id = $1 AND id = $3`, organization, status, person.ID); err != nil {
			t.Fatal(err)
		}
	}
	setStatus("suspended")
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
		t.Errorf("redeem for a suspended account: %v, want %v", err, errs.ErrAuthAccountSuspended)
	}
	setStatus("active")
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, ErrAuthCodeUsed) {
		t.Errorf("redeem again once the account is back: %v, want %v (the code is spent)", err, ErrAuthCodeUsed)
	}

	code, verifier = authorize(public.ClientID)
	if issued, err := svc.ExchangeCode(ctx, public.ClientID, "", code, testRedirect, verifier, ""); err != nil || issued.AccessToken == "" {
		t.Errorf("a public application redeems with its verifier alone: %+v, %v", issued, err)
	}

	exemption := func(c *Client, until *time.Time) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := svc.updateClient(ctx, tx, organization, c.ID, UpdateClientInput{PKCEExemptUntil: OptionalTime{Set: true, At: until}}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	soon, tooLate := time.Now().Add(time.Hour), time.Now().Add(pkceExemptionMax+time.Hour)
	if err := exemption(public, &soon); !errors.Is(err, ErrPKCEExemptionInvalid) {
		t.Errorf("exempt a public application: %v, want %v", err, ErrPKCEExemptionInvalid)
	}
	if err := exemption(client, &tooLate); !errors.Is(err, ErrPKCEExemptionInvalid) {
		t.Errorf("exempt for longer than allowed: %v, want %v", err, ErrPKCEExemptionInvalid)
	}
	if _, _, err := svc.Authorize(ctx, person.ID, public.ClientID, testRedirect, []string{"openid"}, "n-1", "", ""); !errors.Is(err, ErrCodeChallengeRequired) {
		t.Errorf("a public application without a challenge: %v, want %v", err, ErrCodeChallengeRequired)
	}
	if err := exemption(client, &soon); err != nil {
		t.Fatalf("exempt the confidential application: %v", err)
	}
	unproved := func() string {
		t.Helper()
		code, _, err := svc.Authorize(ctx, person.ID, client.ClientID, testRedirect, []string{"openid"}, "", "", "")
		if err != nil {
			t.Fatalf("authorize while exempt: %v", err)
		}
		return code
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, unproved(), testRedirect, "", ""); err != nil {
		t.Errorf("redeem an unproved code while exempt: %v", err)
	}
	code = unproved()
	if err := exemption(client, nil); err != nil {
		t.Fatalf("end the exemption: %v", err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, "", ""); !errors.Is(err, ErrCodeChallengeRequired) {
		t.Errorf("redeem an unproved code after the exemption ended: %v, want %v", err, ErrCodeChallengeRequired)
	}
}

// TestOIDCAuthorizationCodeWithPKCE checks the authorization code grant: the
// code redeems only with its PKCE verifier, once, for tokens naming the user.
func TestOIDCAuthorizationCodeWithPKCE(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, dbtest.Pool(t), issuer)
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)

	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	code, gotOrganization, err := svc.Authorize(ctx, user.ID, client.ClientID, testRedirect, []string{"openid"}, "n-0S6_WzA2Mj", challenge, "S256")
	if err != nil || gotOrganization != organization {
		t.Fatalf("authorize: organization %s, %v", gotOrganization, err)
	}

	wrongVerifier := strings.Repeat("a", 43)
	for name, v := range map[string]string{"missing": "", "wrong": wrongVerifier} {
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, v, ""); err == nil {
			t.Errorf("exchange with %s verifier succeeded", name)
		}
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, "wrong-secret", code, testRedirect, verifier, ""); err == nil {
		t.Error("exchange with a wrong client secret succeeded")
	}

	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if issued.IDToken == "" || issued.RefreshToken == "" {
		t.Errorf("exchange returned id token %t, refresh token %t; want both", issued.IDToken != "", issued.RefreshToken != "")
	}
	claims, err := issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if err != nil || claims.UserID != user.ID || claims.OrganizationID != organization {
		t.Fatalf("access token claims %+v, %v; want user %s in organization %s", claims, err, user.ID, organization)
	}

	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, ErrAuthCodeUsed) {
		t.Errorf("second exchange: %v, want %v", err, ErrAuthCodeUsed)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("refresh token survived the code's replay")
	}
}

// TestExchangeCodeAnswers pins what redeeming a code answers: the proof key
// refusals, which spend nothing; the tokens of a redemption, the ID token
// carrying the authorization's nonce; and, for a code presented again, the
// end of the grant its first redemption bought, recorded.
func TestExchangeCodeAnswers(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, pool, issuer)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := svc.Authorize(ctx, person.ID, client.ClientID, testRedirect, []string{"openid", "profile"}, "nonce-1", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, verifier string
		want           error
	}{
		{"no verifier", "", ErrCodeVerifierRequired},
		{"a verifier too short", "short", ErrCodeVerifierInvalid},
		{"another verifier", other, ErrCodeVerifierInvalid},
	} {
		if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, tc.verifier, ""); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	got, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if got.AccessToken == "" || got.IDToken == "" || got.RefreshToken == "" || got.TokenType != "Bearer" ||
		got.Scope != "openid profile" || got.ExpiresIn != int(issuer.AccessTTL().Seconds()) {
		t.Errorf("redeemed: %+v", got)
	}
	idClaims, err := issuer.VerifySigned(got.IDToken)
	if err != nil || idClaims["nonce"] != "nonce-1" || idClaims["aud"] != client.ClientID || idClaims["sub"] != person.ID.String() {
		t.Errorf("ID token %v, %v: want the nonce, the application and the person", idClaims, err)
	}
	live := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE client_id = $1 AND user_id = $2 AND revoked_at IS NULL`, client.ClientID, person.ID)
	}
	if live() != 1 {
		t.Fatalf("%d live refresh tokens after the redemption, want 1", live())
	}

	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, ErrAuthCodeUsed) {
		t.Errorf("redeemed again: %v, want %v", err, ErrAuthCodeUsed)
	}
	if live() != 0 {
		t.Errorf("%d live refresh tokens after the code came back, want the grant ended", live())
	}
	var meta map[string]any
	if err := pool.QueryRow(ctx, `SELECT metadata FROM audit.events WHERE organization_id = $1 AND action = 'oidc.authorization_code_reused'
		AND actor_user_id = $2 AND actor_type = 'system'`, organization, person.ID).Scan(&meta); err != nil {
		t.Fatalf("the reuse's audit row: %v", err)
	}
	if meta["client_id"] != client.ClientID || meta["grants_revoked"] != float64(1) || meta["reason"] != "authorization_code_reuse" {
		t.Errorf("reuse metadata %v", meta)
	}
}
