//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTokensAnswerOnlyToTheirApplication checks that another application, of
// the same organisation or another, can neither renew, revoke nor learn of an
// application's tokens, that a public client can't introspect at all, and that
// the application itself introspects and revokes them over HTTP.
func TestTokensAnswerOnlyToTheirApplication(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	sibling, siblingSecret := registerClient(t, svc, tenant)
	foreign, foreignSecret := registerClient(t, svc, otherTenant)
	public, _ := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, Type: "public"})
	issued := redeemCode(t, svc, client, secret, person.ID, "")

	for _, caller := range []struct{ name, id, secret string }{
		{"the organisation's other application", sibling.ClientID, siblingSecret},
		{"another organisation's application", foreign.ClientID, foreignSecret},
	} {
		if err := svc.RevokeToken(ctx, caller.id, caller.secret, issued.RefreshToken, ""); err != nil {
			t.Errorf("%s revoking the refresh token: %v, want a silent no-op", caller.name, err)
		}
		if _, err := svc.RefreshToken(ctx, caller.id, caller.secret, issued.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenClientMismatch) {
			t.Errorf("%s renewing the refresh token: %v, want %v", caller.name, err, errs.ErrOIDCRefreshTokenClientMismatch)
		}
		for kind, token := range map[string]string{"access": issued.AccessToken, "refresh": issued.RefreshToken} {
			out, err := svc.Introspect(ctx, caller.id, caller.secret, token, "")
			if err != nil || out["active"] != false || len(out) != 1 {
				t.Errorf("%s introspecting the %s token: %v, %v; want only active false", caller.name, kind, out, err)
			}
		}
	}
	if _, err := svc.Introspect(ctx, public.ClientID, "", issued.AccessToken, ""); !errors.Is(err, errs.ErrOIDCClientAuthFailed) {
		t.Errorf("a public client introspecting: %v, want %v", err, errs.ErrOIDCClientAuthFailed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oidc.client_auth_failed'
		AND metadata->>'reason' = 'public_client'`, tenant); n != 1 {
		t.Errorf("the public client's introspection was audited %d times, want once", n)
	}
	renewed, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("the application's own refresh after the others' attempts: %v", err)
	}

	endpoints := chi.NewRouter()
	(&Handler{Service: svc}).MountPublic(endpoints)
	introspect := func(form url.Values) map[string]any {
		t.Helper()
		var out map[string]any
		dbtest.Decode(t, postForm(t, endpoints, "/oauth/introspect", form, client.ClientID, secret), &out)
		return out
	}
	if out := introspect(url.Values{"token": {renewed.AccessToken}}); out["active"] != true || out["client_id"] != client.ClientID || out["sub"] != person.ID.String() {
		t.Errorf("introspect the application's own access token: %v", out)
	}
	if got, _ := decodeTokenError(t, postForm(t, endpoints, "/oauth/revoke", url.Values{"token": {renewed.AccessToken}}, client.ClientID, secret)); got != "unsupported_token_type" {
		t.Errorf("revoke an access token: %s, want unsupported_token_type", got)
	}
	form := url.Values{"token": {renewed.RefreshToken}, "client_id": {client.ClientID}, "client_secret": {secret}}
	if rec := postForm(t, endpoints, "/oauth/revoke", form, "", ""); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("revoke the refresh token with form credentials: %d %q, want 200 and no body", rec.Code, rec.Body.String())
	}
	if out := introspect(url.Values{"token": {renewed.RefreshToken}, "token_type_hint": {"refresh_token"}}); out["active"] != false {
		t.Errorf("introspect the revoked refresh token: %v, want inactive", out)
	}
}

// TestSuspendedOrganisationRenewsNothing checks that once an organisation is
// suspended its applications' grants renew nothing, as its sign-ins and the
// introspection of its tokens already refuse.
func TestSuspendedOrganisationRenewsNothing(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	issued := redeemCode(t, svc, client, secret, person.ID, "")
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, tenant); err != nil {
		t.Fatal(err)
	}

	if out, err := svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, ""); err != nil || out["active"] != false {
		t.Errorf("introspect after the suspension: %v, %v; want inactive", out, err)
	}
	if renewed, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Errorf("a suspended organisation's grant renewed: access token %t", renewed.AccessToken != "")
	}
}

// TestTokenExchangeRefusesIDTokens checks that token exchange takes only an
// access token as its subject: an ID token, though signed by the same key, is
// refused, even by an application the person has delegated to.
func TestTokenExchangeRefusesIDTokens(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	app, appSecret := registerClient(t, svc, tenant)
	delegate, delegateSecret := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, GrantTypes: []string{"authorization_code", "token_exchange"}})
	if err := svc.GrantConsent(ctx, person.ID, delegate.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	issued := redeemCode(t, svc, app, appSecret, person.ID, "")

	if exchanged, err := svc.TokenExchange(ctx, delegate.ClientID, delegateSecret, issued.IDToken, tokenTypeAccessToken, "", "", "", "", ""); err == nil {
		t.Errorf("an ID token issued to another application was exchanged for an access token (%t)", exchanged.AccessToken != "")
	}
}
