//go:build integration

package oidc

import (
	"errors"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRefreshRotationAndReuse checks that a refresh token rotates, works only
// for its own client and secret, and that presenting a rotated one again ends
// the whole chain as theft, audited.
func TestRefreshRotationAndReuse(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	other, otherSecret := registerClient(t, svc, tenant)
	issued := redeemCode(t, svc, client, secret, user.ID, "")

	if _, err := svc.RefreshToken(ctx, client.ClientID, "wrong-secret", issued.RefreshToken, ""); err == nil {
		t.Error("a refresh with a wrong client secret succeeded")
	}
	if _, err := svc.RefreshToken(ctx, other.ClientID, otherSecret, issued.RefreshToken, ""); err == nil {
		t.Error("another application redeemed the refresh token")
	}
	rotated, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil || rotated.RefreshToken == "" || rotated.RefreshToken == issued.RefreshToken || rotated.AccessToken == "" {
		t.Fatalf("refresh: %+v, %v; want a new pair", rotated, err)
	}

	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("a rotated refresh token was redeemed again")
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, rotated.RefreshToken, ""); err == nil {
		t.Error("the chain's live refresh token survived the reuse of a rotated one")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.refresh_reuse_detected' AND tenant_id = $1`, tenant); n != 1 {
		t.Errorf("the reuse was audited %d times, want once", n)
	}
}

// TestRevocationAndIntrospection checks that introspection reports a token to
// the application it was issued to and to no other; that revoking a refresh
// token ends it while an access token can't be revoked; and that a suspended
// account's access token introspects inactive.
func TestRevocationAndIntrospection(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	other, otherSecret := registerClient(t, svc, tenant)
	issued := redeemCode(t, svc, client, secret, user.ID, "")
	active := func(clientID, clientSecret, token string) bool {
		t.Helper()
		out, err := svc.Introspect(ctx, clientID, clientSecret, token, "")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		return out["active"] == true
	}

	out, err := svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, "")
	if err != nil || out["active"] != true || out["client_id"] != client.ClientID || out["sub"] != user.ID.String() {
		t.Errorf("introspect the access token: %v, %v; want it active, the application's and the user's", out, err)
	}
	if active(other.ClientID, otherSecret, issued.AccessToken) || active(other.ClientID, otherSecret, issued.RefreshToken) {
		t.Error("another application of the organisation learned of the tokens")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.introspection_refused' AND tenant_id = $1`, tenant); n == 0 {
		t.Error("asking about another application's token was not audited")
	}
	if !active(client.ClientID, secret, issued.RefreshToken) {
		t.Error("the live refresh token introspects inactive")
	}

	wantOAuthError(t, "revoke an access token", svc.RevokeToken(ctx, client.ClientID, secret, issued.AccessToken, ""), "unsupported_token_type")
	if err := svc.RevokeToken(ctx, client.ClientID, secret, "not-a-token", ""); err != nil {
		t.Errorf("revoke an unknown token: %v, want success", err)
	}
	if err := svc.RevokeToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err != nil {
		t.Fatalf("revoke the refresh token: %v", err)
	}
	if active(client.ClientID, secret, issued.RefreshToken) {
		t.Error("a revoked refresh token introspects active")
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Error("a revoked refresh token was redeemed")
	}

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if active(client.ClientID, secret, issued.AccessToken) {
		t.Error("a suspended account's access token introspects active")
	}
}

// TestTokenExchange checks that an application exchanges its own token for one
// with no more scope, which can't outlive it, within the exchange depth; and
// that an application without the grant, or another organisation's, can't.
func TestTokenExchange(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(dbtest.Pool(t), issuer)
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	user := dbtest.User(t, tenant, tenant)
	grants := []string{"authorization_code", "refresh_token", "token_exchange"}
	client, secret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: grants})
	plain, plainSecret := registerClient(t, svc, tenant)
	foreign, foreignSecret := registerClientWith(t, svc, CreateClientInput{TenantID: otherTenant, GrantTypes: grants})
	subject := redeemCode(t, svc, client, secret, user.ID, "")
	exchange := func(clientID, clientSecret, token, scope string) (*TokenResponse, error) {
		return svc.TokenExchange(ctx, clientID, clientSecret, token, "", "", scope, "", "", "")
	}

	exchanged, err := exchange(client.ClientID, secret, subject.AccessToken, "openid")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	from, _ := issuer.VerifyAccessAnyAudience(subject.AccessToken)
	claims, err := issuer.VerifyAccessAnyAudience(exchanged.AccessToken)
	if err != nil || claims.UserID != user.ID || claims.ClientID != client.ClientID || claims.ExchangeDepth != 1 ||
		claims.ExpiresAt.After(from.ExpiresAt.Time) {
		t.Fatalf("exchanged token %+v, %v; want the user's, issued to the caller, one exchange deep, expiring no later", claims, err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.token_exchanged' AND tenant_id = $1`, tenant); n != 1 {
		t.Error("the exchange was not audited")
	}

	for _, tc := range []struct {
		name, clientID, clientSecret, scope string
		want                                *errs.Error
	}{
		{"more scope than the subject's", client.ClientID, secret, "openid admin", errs.ErrOIDCScopeExceedsSubject},
		{"an application without the grant", plain.ClientID, plainSecret, "", errs.ErrOIDCGrantTypeNotAllowed},
		{"another organisation's application", foreign.ClientID, foreignSecret, "", errs.ErrOIDCSubjectTokenInvalid},
	} {
		if _, err := exchange(tc.clientID, tc.clientSecret, subject.AccessToken, tc.scope); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	svc.SetTokenExchangeMaxDepth(1)
	if _, err := exchange(client.ClientID, secret, exchanged.AccessToken, ""); !errors.Is(err, errs.ErrOIDCExchangeDepthExceeded) {
		t.Errorf("exchange past the depth: %v, want %v", err, errs.ErrOIDCExchangeDepthExceeded)
	}
}
