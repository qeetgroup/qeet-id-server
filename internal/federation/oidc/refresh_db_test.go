//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestApplicationGrantsMakeAPersonMonthlyActive checks that an application
// redeeming a person's code, and renewing its refresh token, each make the
// person active in the organization this month.
func TestApplicationGrantsMakeAPersonMonthlyActive(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	active := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.monthly_active_users
			WHERE organization_id = $1 AND user_id = $2 AND month = date_trunc('month', NOW() AT TIME ZONE 'UTC')::date`, organization, person.ID)
	}

	first := redeemCode(t, svc, client, secret, person.ID, "")
	if n := active(); n != 1 {
		t.Fatalf("after the code exchange: %d rows, want 1", n)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM organization.monthly_active_users WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, ""); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n := active(); n != 1 {
		t.Fatalf("after the refresh: %d rows, want 1", n)
	}
}

// TestRefreshKeepsTheGrantsResource checks that a refresh can carry forward or
// repeat the resource its grant is bound to while it is registered, and can't
// name another.
func TestRefreshKeepsTheGrantsResource(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, dbtest.Pool(t), issuer)
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	registerResources(t, svc, organization, resourceA, resourceB)

	bound := redeemCode(t, svc, client, secret, user.ID, resourceA)
	_, err := svc.RefreshToken(ctx, client.ClientID, secret, bound.RefreshToken, resourceB)
	wantOAuthError(t, "refresh naming another resource", err, "invalid_target")

	// The refused request spent nothing; the bound resource carries forward.
	carried, err := svc.RefreshToken(ctx, client.ClientID, secret, bound.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh carrying the resource forward: %v", err)
	}
	if _, err := issuer.VerifyAccessFor(carried.AccessToken, resourceA); err != nil {
		t.Errorf("carried-forward access token is not for %s: %v", resourceA, err)
	}
	repeated, err := svc.RefreshToken(ctx, client.ClientID, secret, carried.RefreshToken, resourceA)
	if err != nil {
		t.Fatalf("refresh repeating the bound resource: %v", err)
	}
	if _, err := issuer.VerifyAccessFor(repeated.AccessToken, resourceA); err != nil {
		t.Errorf("repeated-resource access token is not for %s: %v", resourceA, err)
	}

	// A grant bound to no resource can't gain one on refresh.
	unbound := redeemCode(t, svc, client, secret, user.ID, "")
	_, err = svc.RefreshToken(ctx, client.ClientID, secret, unbound.RefreshToken, resourceA)
	wantOAuthError(t, "refresh of an unbound grant naming a resource", err, "invalid_target")
	plain, err := svc.RefreshToken(ctx, client.ClientID, secret, unbound.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh of an unbound grant: %v", err)
	}
	if _, err := issuer.VerifyAccess(plain.AccessToken); err != nil {
		t.Errorf("unbound grant's access token is not for the platform: %v", err)
	}

	// Once the bound resource is removed, a refresh carrying it forward is
	// refused like one naming it.
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.oidc_resources WHERE organization_id = $1 AND identifier = $2`, organization, resourceA); err != nil {
		t.Fatal(err)
	}
	_, err = svc.RefreshToken(ctx, client.ClientID, secret, repeated.RefreshToken, "")
	wantOAuthError(t, "refresh carrying a removed resource forward", err, "invalid_target")
}

// TestRefreshDropsScopesTheClientNoLongerHas checks that a refresh carries
// forward only the granted scopes the application still registers, says so in
// its scope, and keeps the narrower set for later refreshes; and that a grant
// left with none of its scopes renews nothing.
func TestRefreshDropsScopesTheClientNoLongerHas(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, dbtest.Pool(t), issuer)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	register := func(scopes ...string) {
		t.Helper()
		if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.oidc_clients SET scopes = $2 WHERE client_id = $1`, client.ClientID, scopes); err != nil {
			t.Fatal(err)
		}
	}
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := svc.Authorize(ctx, person.ID, client.ClientID, testRedirect, []string{"openid", "email"}, "n-1", challenge, "S256")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	register("openid", "profile")
	refreshed, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh after the application dropped email: %v", err)
	}
	claims, err := issuer.VerifyAccess(refreshed.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Scope != "openid" || claims.Scope != "openid" || refreshed.IDToken == "" {
		t.Errorf("refresh after the application dropped email: scope %q, token scope %q, id token %t; want openid only",
			refreshed.Scope, claims.Scope, refreshed.IDToken != "")
	}

	// Registering email again doesn't bring it back without a new consent.
	register("openid", "profile", "email")
	again, err := svc.RefreshToken(ctx, client.ClientID, secret, refreshed.RefreshToken, "")
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if again.Scope != "openid" {
		t.Errorf("second refresh: scope %q, want openid", again.Scope)
	}

	register("profile")
	_, err = svc.RefreshToken(ctx, client.ClientID, secret, again.RefreshToken, "")
	wantOAuthError(t, "refresh of a grant none of whose scopes the application still registers", err, "invalid_scope")
}

// TestRefreshedIDTokenKeepsTheSignIn checks that an ID token issued again on a
// refresh, and on the refresh after it, reports the original sign-in's
// auth_time and hosted-login session (OIDC Core 12.2), and no nonce.
func TestRefreshedIDTokenKeepsTheSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, p.svc, organization)
	cookie, sessionID := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, client.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	target, verifier := authorizeURL(t, client.ClientID)
	_, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	issued, err := p.svc.ExchangeCode(ctx, client.ClientID, secret, q.Get("code"), testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem the code: %v", err)
	}
	first, err := p.svc.issuer.VerifySigned(issued.IDToken)
	if err != nil || first["auth_time"] == nil || first["sid"] != sessionID.String() {
		t.Fatalf("first ID token %v, %v; want auth_time and the session", first, err)
	}

	refresh := issued.RefreshToken
	for i := 1; i <= 2; i++ {
		renewed, err := p.svc.RefreshToken(ctx, client.ClientID, secret, refresh, "")
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		id, err := p.svc.issuer.VerifySigned(renewed.IDToken)
		if err != nil {
			t.Fatalf("refresh %d: verify the ID token: %v", i, err)
		}
		if id["auth_time"] != first["auth_time"] || id["sid"] != first["sid"] || id["sub"] != first["sub"] || id["aud"] != first["aud"] {
			t.Errorf("refresh %d: ID token %v, want the first one's auth_time, sid, sub and aud (%v)", i, id, first)
		}
		if _, ok := id["nonce"]; ok {
			t.Errorf("refresh %d: the ID token carries a nonce", i)
		}
		refresh = renewed.RefreshToken
	}
}

// TestSuspendedOrganizationRenewsNothing checks that once an organization is
// suspended its applications' grants renew nothing, as its sign-ins and the
// introspection of its tokens already refuse.
func TestSuspendedOrganizationRenewsNothing(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	issued := redeemCode(t, svc, client, secret, person.ID, "")
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE organization.organizations SET status = 'suspended' WHERE id = $1`, organization); err != nil {
		t.Fatal(err)
	}

	if out, err := svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, ""); err != nil || out["active"] != false {
		t.Errorf("introspect after the suspension: %v, %v; want inactive", out, err)
	}
	if renewed, err := svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err == nil {
		t.Errorf("a suspended organization's grant renewed: access token %t", renewed.AccessToken != "")
	}
}

// TestRefreshRotationAndReuse checks that a refresh token rotates, works only
// for its own client and secret, and that presenting a rotated one again ends
// the whole chain as theft, audited.
func TestRefreshRotationAndReuse(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	other, otherSecret := registerClient(t, svc, organization)
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.refresh_reuse_detected' AND organization_id = $1`, organization); n != 1 {
		t.Errorf("the reuse was audited %d times, want once", n)
	}
}

// TestRefreshTokenAnswers pins what renewing a refresh token answers, in the
// order it checks, and what each answer leaves behind: a rotated token whose
// old one is spent, the whole chain ended for a suspended account or a token
// presented twice, and the reuse recorded.
func TestRefreshTokenAnswers(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	svc := newTestService(t, pool, dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	client, secret := registerClient(t, svc, organization)
	sibling, siblingSecret := registerClient(t, svc, organization)
	live := func(userID uuid.UUID) int {
		return dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE client_id = $1 AND user_id = $2 AND revoked_at IS NULL AND used_at IS NULL`, client.ClientID, userID)
	}

	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, "", ""); !errors.Is(err, ErrRefreshTokenRequired) {
		t.Errorf("no token: %v, want %v", err, ErrRefreshTokenRequired)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, "not-a-token", ""); !errors.Is(err, ErrRefreshTokenInvalid) {
		t.Errorf("an unknown token: %v, want %v", err, ErrRefreshTokenInvalid)
	}
	first := redeemCode(t, svc, client, secret, person.ID, "")
	if _, err := svc.RefreshToken(ctx, sibling.ClientID, siblingSecret, first.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenClientMismatch) {
		t.Errorf("another application's token: %v, want %v", err, ErrRefreshTokenClientMismatch)
	}
	renewed, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, "")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.AccessToken == "" || renewed.IDToken == "" || renewed.RefreshToken == "" || renewed.RefreshToken == first.RefreshToken ||
		renewed.TokenType != "Bearer" || renewed.Scope != first.Scope {
		t.Errorf("renewed: %+v, want new tokens for %q", renewed, first.Scope)
	}
	if live(person.ID) != 1 {
		t.Errorf("%d live refresh tokens after a rotation, want the new one", live(person.ID))
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, first.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenReuse) {
		t.Errorf("the spent token again: %v, want %v", err, ErrRefreshTokenReuse)
	}
	if live(person.ID) != 0 {
		t.Errorf("%d live refresh tokens after a reuse, want the chain ended", live(person.ID))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oidc.refresh_reuse_detected'
		AND actor_user_id = $2 AND actor_type = 'system' AND metadata->>'client_id' = $3`, organization, person.ID, client.ClientID); n != 1 {
		t.Errorf("%d reuse rows, want 1", n)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, renewed.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("a token of the ended chain: %v, want %v", err, ErrRefreshTokenRevoked)
	}

	theirs := redeemCode(t, svc, client, secret, other.ID, "")
	if _, err := pool.Exec(ctx, `UPDATE auth.oidc_refresh_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE client_id = $1 AND user_id = $2`, client.ClientID, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, theirs.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenExpired) {
		t.Errorf("an expired token: %v, want %v", err, ErrRefreshTokenExpired)
	}
	theirs = redeemCode(t, svc, client, secret, other.ID, "")
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, other.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshToken(ctx, client.ClientID, secret, theirs.RefreshToken, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
		t.Errorf("a suspended account's token: %v, want %v", err, errs.ErrAuthAccountSuspended)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE client_id = $1 AND user_id = $2 AND revoked_at IS NULL`, client.ClientID, other.ID); n != 0 {
		t.Errorf("%d unrevoked refresh tokens of a suspended account, want none", n)
	}
}
