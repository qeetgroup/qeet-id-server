//go:build integration

package oidc

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestTokenExchangeRefusesIDTokens checks that token exchange takes only an
// access token as its subject: an ID token, though signed by the same key, is
// refused, even by an application the person has delegated to.
func TestTokenExchangeRefusesIDTokens(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	app, appSecret := registerClient(t, svc, organization)
	delegate, delegateSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{"authorization_code", "token_exchange"}})
	if err := svc.GrantConsent(ctx, person.ID, delegate.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	issued := redeemCode(t, svc, app, appSecret, person.ID, "")

	if exchanged, err := svc.TokenExchange(ctx, delegate.ClientID, delegateSecret, issued.IDToken, tokenTypeAccessToken, "", "", "", "", ""); err == nil {
		t.Errorf("an ID token issued to another application was exchanged for an access token (%t)", exchanged.AccessToken != "")
	}
}

// TestTokenExchange checks that an application exchanges its own token for one
// with no more scope, which can't outlive it, within the exchange depth; and
// that an application without the grant, or another organization's, can't.
func TestTokenExchange(t *testing.T) {
	ctx := dbtest.Context(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, dbtest.Pool(t), issuer)
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	grants := []string{"authorization_code", "refresh_token", "token_exchange"}
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants})
	plain, plainSecret := registerClient(t, svc, organization)
	foreign, foreignSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: otherOrganization, GrantTypes: grants})
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.token_exchanged' AND organization_id = $1`, organization); n != 1 {
		t.Error("the exchange was not audited")
	}

	for _, tc := range []struct {
		name, clientID, clientSecret, scope string
		want                                *errs.Error
	}{
		{"more scope than the subject's", client.ClientID, secret, "openid admin", ErrScopeExceedsSubject},
		{"an application without the grant", plain.ClientID, plainSecret, "", ErrGrantTypeNotAllowed},
		{"another organization's application", foreign.ClientID, foreignSecret, "", ErrSubjectTokenInvalid},
	} {
		if _, err := exchange(tc.clientID, tc.clientSecret, subject.AccessToken, tc.scope); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	twice, err := exchange(client.ClientID, secret, exchanged.AccessToken, "")
	if err != nil {
		t.Fatalf("exchange an exchanged token: %v", err)
	}
	if _, err := exchange(client.ClientID, secret, twice.AccessToken, ""); !errors.Is(err, ErrExchangeDepthExceeded) {
		t.Errorf("exchange past the depth: %v, want %v", err, ErrExchangeDepthExceeded)
	}
}

// TestTokenExchangeHoldsOnlyWhatTheCallerMay checks that an application
// exchanging a person's token it holds by their consent gets no scope beyond
// those consented to and those it is registered for.
func TestTokenExchangeHoldsOnlyWhatTheCallerMay(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newTestService(t, dbtest.Pool(t), dbtest.Issuer(t))
	organization := dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	grants := []string{"authorization_code", "refresh_token", "token_exchange"}
	app, appSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants, Scopes: []string{"openid", "email", "profile"}})
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := svc.Authorize(ctx, user.ID, app.ClientID, testRedirect, []string{"openid", "email", "profile"}, "n-1", challenge, "S256")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := svc.ExchangeCode(ctx, app.ClientID, appSecret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatal(err)
	}
	delegate, delegateSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants, Scopes: []string{"openid", "email", "profile"}})
	narrow, narrowSecret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants, Scopes: []string{"openid"}})
	for _, c := range []*Client{delegate, narrow} {
		if err := svc.GrantConsent(ctx, user.ID, c.ClientID, []string{"openid", "email"}); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name, clientID, secret, scope, want string
		err                                 *errs.Error
	}{
		{"by consent, asking nothing", delegate.ClientID, delegateSecret, "", "openid email", nil},
		{"by consent, asking beyond it", delegate.ClientID, delegateSecret, "profile", "", ErrScopeExceedsSubject},
		{"by consent, registered for less", narrow.ClientID, narrowSecret, "", "openid", nil},
		{"by consent, asking beyond its registration", narrow.ClientID, narrowSecret, "email", "", ErrScopeExceedsSubject},
	} {
		got, err := svc.TokenExchange(ctx, tc.clientID, tc.secret, subject.AccessToken, "", "", tc.scope, "", "", "")
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: %v, want %v", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || got.Scope != tc.want {
			t.Errorf("%s: %+v, %v; want scope %q", tc.name, got, err, tc.want)
		}
	}
}

// TestTokenExchangeAnswers pins what token exchange answers for each kind of
// request, in the order it checks them, and what a granted exchange issues and
// records: an access token issued to the caller, naming its actor, never
// outliving the subject, and one audit row about it.
func TestTokenExchangeAnswers(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	issuer := dbtest.Issuer(t)
	svc := newTestService(t, pool, issuer)
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	user := dbtest.User(t, organization, organization)
	grants := []string{"authorization_code", "refresh_token", "token_exchange"}
	client, secret := registerClientWith(t, svc, CreateClientInput{OrganizationID: organization, GrantTypes: grants})
	subject := redeemCode(t, svc, client, secret, user.ID, "")
	actor, _, err := issuer.IssueAccess(user.ID, organization, uuid.New(), "openid")
	if err != nil {
		t.Fatal(err)
	}
	foreignActor, _, err := issuer.IssueAccess(user.ID, otherOrganization, uuid.New(), "openid")
	if err != nil {
		t.Fatal(err)
	}
	type request struct{ subject, subjectType, requestedType, scope, actor, actorType string }
	exchange := func(r request) (*TokenResponse, error) {
		return svc.TokenExchange(ctx, client.ClientID, secret, r.subject, r.subjectType, r.requestedType, r.scope, r.actor, r.actorType, "")
	}
	for _, tc := range []struct {
		name string
		req  request
		want *errs.Error
	}{
		{"no subject token", request{}, ErrSubjectTokenRequired},
		{"a subject token of another type", request{subject: subject.AccessToken, subjectType: "urn:ietf:params:oauth:token-type:id_token"}, ErrSubjectTokenTypeUnsupported},
		{"another requested token type", request{subject: subject.AccessToken, requestedType: "urn:ietf:params:oauth:token-type:refresh_token"}, ErrRequestedTokenTypeUnsupported},
		{"a subject token that isn't one", request{subject: "not-a-token"}, ErrSubjectTokenInvalid},
		{"an actor token of another type", request{subject: subject.AccessToken, actor: actor, actorType: "urn:ietf:params:oauth:token-type:id_token"}, ErrActorTokenTypeUnsupported},
		{"an actor token that isn't one", request{subject: subject.AccessToken, actor: "not-a-token"}, ErrActorTokenInvalid},
		{"an actor of another organization", request{subject: subject.AccessToken, actor: foreignActor}, ErrActorTokenInvalid},
	} {
		if _, err := exchange(tc.req); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'oidc.token_exchanged' AND organization_id = $1`, organization); n != 0 {
		t.Errorf("%d exchanges recorded for refused requests, want none", n)
	}

	got, err := exchange(request{subject: subject.AccessToken, subjectType: tokenTypeAccessToken, requestedType: tokenTypeAccessToken, scope: "openid", actor: actor, actorType: tokenTypeAccessToken})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	from, _ := issuer.VerifyAccessAnyAudience(subject.AccessToken)
	claims, err := issuer.VerifyAccessAnyAudience(got.AccessToken)
	if err != nil || got.TokenType != "Bearer" || got.IssuedTokenType != tokenTypeAccessToken || got.Scope != "openid" ||
		got.RefreshToken != "" || got.IDToken != "" || got.ExpiresIn <= 0 {
		t.Fatalf("exchanged: %+v, %v", got, err)
	}
	if claims.Act == nil || claims.Act.Subject != user.ID.String() || claims.ClientID != client.ClientID || claims.ExchangeDepth != 1 ||
		claims.SessionID == from.SessionID || claims.ExpiresAt.After(from.ExpiresAt.Time) {
		t.Errorf("exchanged claims %+v: want the actor, the caller, depth 1, a session of its own, expiring no later", claims)
	}
	var meta map[string]any
	if err := pool.QueryRow(ctx, `SELECT metadata FROM audit.events WHERE action = 'oidc.token_exchanged' AND organization_id = $1 AND actor_user_id = $2 AND actor_type = 'client'`,
		organization, user.ID).Scan(&meta); err != nil {
		t.Fatalf("the exchange's audit row: %v", err)
	}
	if meta["client_id"] != client.ClientID || meta["scope"] != "openid" || meta["actor"] != user.ID.String() ||
		meta["session_id"] != claims.SessionID.String() || meta["exchange_depth"] != float64(1) || meta["subject_client_id"] != client.ClientID {
		t.Errorf("audit metadata %v", meta)
	}
	if _, linked := meta["from_session_id"]; linked != (from.SessionID != uuid.Nil) {
		t.Errorf("audit metadata %v: from_session_id only for a subject with a session", meta)
	}

	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(request{subject: subject.AccessToken}); !errors.Is(err, errs.ErrAuthAccountSuspended) {
		t.Errorf("a suspended person's token: %v, want %v", err, errs.ErrAuthAccountSuspended)
	}
}
