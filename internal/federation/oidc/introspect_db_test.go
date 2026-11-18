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
// the same organization or another, can neither renew, revoke nor learn of an
// application's tokens, that a public client can't introspect at all, and that
// the application itself introspects and revokes them over HTTP.
func TestTokensAnswerOnlyToTheirApplication(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	sibling, siblingSecret := registerClient(t, svc, organization)
	foreign, foreignSecret := registerClient(t, svc, otherOrganization)
	public, _ := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, Type: "public"})
	issued := redeemCode(t, svc, client, secret, person.ID, "")

	for _, caller := range []struct{ name, id, secret string }{
		{"the organization's other application", sibling.ClientID, siblingSecret},
		{"another organization's application", foreign.ClientID, foreignSecret},
	} {
		if err := svc.RevokeToken(ctx, caller.id, caller.secret, issued.RefreshToken, ""); err != nil {
			t.Errorf("%s revoking the refresh token: %v, want a silent no-op", caller.name, err)
		}
		if _, err := svc.RefreshToken(ctx, caller.id, caller.secret, issued.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenClientMismatch) {
			t.Errorf("%s renewing the refresh token: %v, want %v", caller.name, err, ErrRefreshTokenClientMismatch)
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oidc.client_auth_failed'
		AND metadata->>'reason' = 'public_client'`, organization); n != 1 {
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

// TestRevocationAndIntrospection checks that introspection reports a token to
// the application it was issued to and to no other; that revoking a refresh
// token ends it while an access token can't be revoked; and that a suspended
// account's access token introspects inactive.
func TestRevocationAndIntrospection(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := NewService(dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	other, otherSecret := registerClient(t, svc, organization)
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
		t.Error("another application of the organization learned of the tokens")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.introspection_refused' AND organization_id = $1`, organization); n == 0 {
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

	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if active(client.ClientID, secret, issued.AccessToken) {
		t.Error("a suspended account's access token introspects active")
	}
}
