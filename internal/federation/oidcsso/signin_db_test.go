//go:build integration

package oidcsso

// Database tests for sign-in through an organization's OpenID Connect
// provider: a fake provider (fakeidp_test.go) answers the authorization
// request /oidc-connections/{id}/login sends it, and the callback and
// exchange turn its ID token into a session.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func sessionOrganization(t *testing.T, sessionID uuid.UUID) uuid.UUID {
	t.Helper()
	var organization uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT organization_id FROM auth.sessions WHERE id = $1`, sessionID).Scan(&organization); err != nil {
		t.Fatalf("session %s: %v", sessionID, err)
	}
	return organization
}

// TestOIDCSignIn checks that the provider's ID token buys a session in the
// organization through a one-time code, adopting a verified member on its
// verified domain and provisioning a newcomer there; that the state and the
// code are each spent once; and that the subject stays linked to its person.
func TestOIDCSignIn(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	verify(t, member.ID)

	authURL := s.begin(t, conn.ID)
	idp.expect(t, authURL, "code-1", as(idp, "entra-asha", strings.ToUpper(member.Email), func(c jwt.MapClaims) {
		c["groups"] = []string{"engineering", "oncall"}
	}), nil, "")
	completed := s.callback(t, conn.ID, authURL, "code-1", nil)
	code := loginCode(t, completed)
	if replay := s.callback(t, conn.ID, authURL, "code-1", nil); !strings.Contains(replay.Body.String(), CodeStateInvalid) {
		t.Errorf("the same answer brought back again: %d %s, want %s", replay.Code, replay.Body.String(), CodeStateInvalid)
	}
	if n := failures(t, organization, CodeStateInvalid); n != 1 {
		t.Errorf("%d replays recorded as failed sign-ins, want 1", n)
	}
	rec := s.exchange(t, code)
	var pair authentication.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID || sessionOrganization(t, pair.SessionID) != organization {
		t.Fatalf("exchange: %d %s; want a session for the member in the organization", rec.Code, rec.Body.String())
	}
	refused(t, "a one-time code used again", s.exchange(t, code), CodeLoginCodeUsed)
	refused(t, "an unknown code", s.exchange(t, "not-a-code"), CodeLoginCodeInvalid)
	refused(t, "no code", s.exchange(t, ""), CodeLoginCodeRequired)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id = $2 AND provider = 'oidc'
		AND connection_id = $3 AND subject = $4 AND metadata->'groups' = '["engineering", "oncall"]'::jsonb`,
		member.ID, organization, conn.ID, idp.URL+"#entra-asha"); n != 1 {
		t.Errorf("%d identities linked for the member to the connection with their groups, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.login_succeeded' AND metadata->>'method' = 'oidc'`, organization); n != 1 {
		t.Errorf("%d OpenID Connect sign-ins recorded, want 1", n)
	}
	var got Connection
	dbtest.Decode(t, dbtest.Do(t, s.admin(t, organization), http.MethodGet, "/organizations/"+organization.String()+"/oidc-connections/"+conn.ID.String(), nil), &got)
	if got.LastLoginAt == nil {
		t.Error("the connection's last sign-in was not recorded")
	}

	// The linked subject signs in the same person, whatever address it carries.
	if again := s.signIn(t, idp, conn.ID, as(idp, "entra-asha", dbtest.Unique("renamed")+"@example.test", nil)); again.UserID != member.ID {
		t.Errorf("the linked subject signed in %s, want the member %s", again.UserID, member.ID)
	}

	newcomer := dbtest.Unique("newcomer") + "@" + domain
	joined := s.signIn(t, idp, conn.ID, as(idp, "entra-newcomer", newcomer, func(c jwt.MapClaims) {
		delete(c, "name")
		c["given_name"], c["family_name"] = "Ravi", "Iyer"
	}))
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE id = $1 AND organization_id = $2 AND email = $3
		AND email_verified_at IS NOT NULL AND display_name = 'Ravi Iyer'`, joined.UserID, organization, newcomer); n != 1 {
		t.Errorf("the newcomer was not provisioned into the organization, verified and named")
	}

	// A draft connection signs nobody in.
	draft := s.connect(t, organization, idp, map[string]any{"status": "draft"})
	rec = s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+draft.ID.String()+"/login", nil))
	refused(t, "a draft connection's sign-in", rec, CodeConnectionDraft)
	rec = s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+uuid.NewString()+"/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("an unknown connection's sign-in: %d, want 404", rec.Code)
	}
}

// TestOIDCSignInRefusesBadIDTokens checks that an ID token signed by another
// key, from another issuer, for another client, with another sign-in's nonce,
// or expired signs nobody in, and that each refusal is recorded.
func TestOIDCSignInRefusesBadIDTokens(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	email := dbtest.Unique("asha") + "@" + dbtest.Domain(t, organization)
	stranger := newECKey(t)

	bad := map[string]func(*testing.T) *httptest.ResponseRecorder{
		"signed by a key the provider doesn't publish": func(t *testing.T) *httptest.ResponseRecorder {
			authURL := s.begin(t, conn.ID)
			idp.expect(t, authURL, "code-key", as(idp, "u-1", email, nil), stranger, "key-1")
			return s.callback(t, conn.ID, authURL, "code-key", nil)
		},
		"from another issuer": func(t *testing.T) *httptest.ResponseRecorder {
			return s.answer(t, idp, conn.ID, as(idp, "u-1", email, func(c jwt.MapClaims) { c["iss"] = "https://evil.example.test" }))
		},
		"for another client": func(t *testing.T) *httptest.ResponseRecorder {
			return s.answer(t, idp, conn.ID, as(idp, "u-1", email, func(c jwt.MapClaims) { c["aud"] = "another-client" }))
		},
		"with another sign-in's nonce": func(t *testing.T) *httptest.ResponseRecorder {
			return s.answer(t, idp, conn.ID, func(string) jwt.MapClaims { return idp.claimsFor("someone-elses-nonce", "u-1", email) })
		},
		"expired": func(t *testing.T) *httptest.ResponseRecorder {
			return s.answer(t, idp, conn.ID, as(idp, "u-1", email, func(c jwt.MapClaims) { c["exp"] = c["iat"].(int64) - 3600 }))
		},
	}
	for name, run := range bad {
		refused(t, "a token "+name, run(t), ErrIDTokenInvalid.Code)
	}
	if n := failures(t, organization, ErrIDTokenInvalid.Code); n != len(bad) {
		t.Errorf("%d refused tokens recorded, want %d", n, len(bad))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email); n != 0 {
		t.Errorf("a refused token provisioned an account")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE connection_id = $1`, conn.ID); n != 0 {
		t.Errorf("%d login codes issued for refused tokens, want none", n)
	}

	// A provider that refuses answers with an error, spending the state.
	authURL := s.begin(t, conn.ID)
	refused(t, "the provider's refusal", s.callback(t, conn.ID, authURL, "", url.Values{"error": {"access_denied"}}), CodeProviderRefused)
	refused(t, "the refused sign-in again", s.callback(t, conn.ID, authURL, "code", nil), CodeStateInvalid)
	// A code the provider won't redeem fails the exchange.
	refused(t, "a code the provider doesn't know", s.callback(t, conn.ID, s.begin(t, conn.ID), "unknown-code", nil), CodeTokenExchangeFailed)
}

// TestOIDCSignInBindsTheBrowser checks that a sign-in completes only in the
// browser that began it, and that a callback elsewhere spends it.
func TestOIDCSignInBindsTheBrowser(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	email := dbtest.Unique("asha") + "@" + dbtest.Domain(t, organization)

	authURL := s.begin(t, conn.ID)
	idp.expect(t, authURL, "code-1", as(idp, "u-1", email, nil), nil, "")
	held := s.browser
	s.browser = nil
	refused(t, "the callback in another browser", s.callback(t, conn.ID, authURL, "code-1", nil), CodeOtherBrowser)
	s.browser = held
	refused(t, "the spent sign-in in its own browser", s.callback(t, conn.ID, authURL, "code-1", nil), CodeStateInvalid)

	// One connection's sign-in doesn't complete at another's callback.
	other := s.connect(t, organization, idp, nil)
	authURL = s.begin(t, conn.ID)
	idp.expect(t, authURL, "code-2", as(idp, "u-1", email, nil), nil, "")
	refused(t, "the sign-in at another connection's callback", s.callback(t, other.ID, authURL, "code-2", nil), CodeStateInvalid)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email); n != 0 {
		t.Errorf("a refused sign-in provisioned an account")
	}
}

// TestOIDCSignInAdoptsOnlyOnVerifiedDomains checks the accounts a sign-in may
// adopt or create: only on a domain the organization has verified, not when
// the provider calls the address unverified (a provider that doesn't say is
// trusted there), and never an unverified, administering or foreign account.
func TestOIDCSignInAdoptsOnlyOnVerifiedDomains(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	domain, othersDomain := dbtest.Domain(t, organization), dbtest.Domain(t, other)

	refused(t, "an address on no verified domain",
		s.answer(t, idp, conn.ID, as(idp, "u-unverified", dbtest.Unique("x")+"@example.test", nil)), CodeEmailDomainUnverified)
	foreign := dbtest.UserAt(t, dbtest.Unique("y")+"@"+othersDomain, other, other)
	verify(t, foreign.ID)
	refused(t, "another organization's domain",
		s.answer(t, idp, conn.ID, as(idp, "u-foreign", foreign.Email, nil)), CodeEmailDomainUnverified)
	refused(t, "an address the provider calls unverified",
		s.answer(t, idp, conn.ID, as(idp, "u-false", dbtest.Unique("z")+"@"+domain, func(c jwt.MapClaims) { c["email_verified"] = false })),
		CodeEmailUnverified)
	unverified := dbtest.UserAt(t, dbtest.Unique("squatter")+"@"+domain, organization, organization)
	refused(t, "an account that never proved its address",
		s.answer(t, idp, conn.ID, as(idp, "u-squatter", unverified.Email, nil)), CodeAccountUnverified)
	owner := dbtest.UserAt(t, dbtest.Unique("owner")+"@"+domain, organization)
	verify(t, owner.ID)
	dbtest.Assign(t, owner.ID, organization, dbtest.Role(t, organization, "connection.write"))
	refused(t, "an administrator", s.answer(t, idp, conn.ID, as(idp, "u-owner", owner.Email, nil)), CodeAccountAdministers)
	guest := dbtest.UserAt(t, dbtest.Unique("guest")+"@"+domain, other, organization)
	verify(t, guest.ID)
	refused(t, "a guest whose home is elsewhere", s.answer(t, idp, conn.ID, as(idp, "u-guest", guest.Email, nil)), CodeUserOrganizationMismatch)
	for _, refusedUser := range []uuid.UUID{foreign.ID, unverified.ID, owner.ID, guest.ID} {
		if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1`, refusedUser); n != 0 {
			t.Errorf("a refused account %s was linked", refusedUser)
		}
	}

	// Microsoft Entra ID sends no email_verified: the verified domain vouches.
	entra := dbtest.UserAt(t, dbtest.Unique("entra")+"@"+domain, organization, organization)
	verify(t, entra.ID)
	if pair := s.signIn(t, idp, conn.ID, as(idp, "u-entra", entra.Email, func(c jwt.MapClaims) { delete(c, "email_verified") })); pair.UserID != entra.ID {
		t.Errorf("a token that doesn't say signed in %s, want the member %s", pair.UserID, entra.ID)
	}
	if n := failures(t, organization, CodeAccountAdministers); n != 1 {
		t.Errorf("%d refused administrator sign-ins recorded, want 1", n)
	}
}

// TestOIDCSignInEntraTenants checks that a provider serving many tenants signs
// in only the tenants a connection lists, and that a connection listing none
// can't sign anyone in through it.
func TestOIDCSignInEntraTenants(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	idp.issuer = idp.URL + "/{tenantid}/v2.0"
	idp.authMethods = []string{"client_secret_post", "private_key_jwt"}
	const mine, theirs = "6f1c7a52-8c1e-4a43-9a8e-2d6f0b0f5f11", "0e3b5f11-1111-4c2a-8f2e-7a1d3c9b2e22"
	organization := dbtest.Organization(t)
	discovery := idp.URL + "/.well-known/openid-configuration"
	conn := s.connect(t, organization, idp, map[string]any{
		"issuer": idp.URL + "/organizations/v2.0", "discovery_url": discovery, "allowed_idp_tenant_ids": []string{mine},
	})
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	from := func(tid string) func(jwt.MapClaims) {
		return func(c jwt.MapClaims) {
			c["iss"], c["tid"] = idp.URL+"/"+tid+"/v2.0", tid
			delete(c, "email_verified")
		}
	}
	if pair := s.signIn(t, idp, conn.ID, as(idp, "u-1", member.Email, from(mine))); pair.UserID != member.ID {
		t.Errorf("a listed tenant signed in %s, want the member", pair.UserID)
	}
	refused(t, "a tenant the connection doesn't list", s.answer(t, idp, conn.ID, as(idp, "u-1", member.Email, from(theirs))), ErrIDTokenInvalid.Code)

	open := s.connect(t, organization, idp, map[string]any{"issuer": idp.URL + "/organizations/v2.0", "discovery_url": discovery})
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+open.ID.String()+"/login", nil))
	refused(t, "a connection listing no tenants of a multi-tenant provider", rec, CodeMisconfigured)
}

// TestOIDCSignInProvisionsOnlyWithJIT checks that a sign-in creates an
// account only while the domain that manages the address has just-in-time
// provisioning on, and adopts an existing member's account either way.
func TestOIDCSignInProvisionsOnlyWithJIT(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	domain := dbtest.Domain(t, organization)
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE organization.domains SET jit_enabled = FALSE WHERE organization_id = $1`, organization); err != nil {
		t.Fatal(err)
	}
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	verify(t, member.ID)
	newcomer := dbtest.Unique("bea") + "@" + domain

	refused(t, "a newcomer with provisioning off", s.answer(t, idp, conn.ID, as(idp, "u-new", newcomer, nil)), CodeJITNotAllowed)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, newcomer); n != 0 {
		t.Errorf("a refused newcomer was given %d accounts", n)
	}
	if pair := s.signIn(t, idp, conn.ID, as(idp, "u-member", member.Email, nil)); pair.UserID != member.ID {
		t.Errorf("the member's sign-in with provisioning off: %s, want %s", pair.UserID, member.ID)
	}
}

// TestOIDCSignInNeedsSSOInThePlan checks that a sign-in through a connection
// needs a plan with single sign-on when it starts and again when the answer
// arrives, so a plan that lapsed in between signs no one in.
func TestOIDCSignInNeedsSSOInThePlan(t *testing.T) {
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	email := dbtest.Unique("asha") + "@" + dbtest.Domain(t, organization)

	authURL := s.begin(t, conn.ID)
	idp.expect(t, authURL, "code-1", as(idp, "u-1", email, nil), nil, "")
	s.plan.lapsed = true
	refused(t, "the answer after the plan lapsed", s.callback(t, conn.ID, authURL, "code-1", nil), errs.CodeUpgradeRequired)
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+conn.ID.String()+"/login", nil))
	refused(t, "a sign-in started on a plan without single sign-on", rec, errs.CodeUpgradeRequired)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email); n != 0 {
		t.Errorf("a sign-in refused for the plan provisioned %d accounts", n)
	}
}

// TestAHostedSignInTheProviderRefusesReturnsToTheHostedLogin checks that a sign-in the hosted
// login began, which the provider then refuses, goes back to the hosted login's sign-in page with
// a generic error and its return address, and is still recorded for the organization.
func TestAHostedSignInTheProviderRefusesReturnsToTheHostedLogin(t *testing.T) {
	const accounts = "https://accounts.example.test"
	s := newRP(t, func(d *Deps) { d.LoginBaseURL, d.ReturnOrigins = accounts, []string{testPublicBase} })
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	returnTo := testPublicBase + "/oauth/authorize?client_id=portal&state=s1"

	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet,
		"/oidc-connections/"+conn.ID.String()+"/login?return_to="+url.QueryEscape(returnTo), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login with return_to: %d %s", rec.Code, rec.Body.String())
	}
	answered := s.callback(t, conn.ID, rec.Header().Get("Location"), "", url.Values{"error": {"access_denied"}})
	want := accounts + "/sign-in?" + url.Values{"error": {"sso"}, "return_to": {returnTo}}.Encode()
	if got := answered.Header().Get("Location"); answered.Code != http.StatusFound || got != want {
		t.Fatalf("callback: %d %s %s, want the hosted login's sign-in with the error", answered.Code, got, answered.Body.String())
	}
	if n := failures(t, organization, CodeProviderRefused); n != 1 {
		t.Errorf("%d refusals recorded, want 1", n)
	}
}

// TestOIDCSignInSyncsGroupsAndName checks that a sign-in keeps the account in
// step with the ID token as SAML and LDAP sign-in do: the groups its groups
// claim reaches, by the connection's mappings or a SCIM group's external id,
// its display name, and its address only when the provider vouches for it.
// Withheld groups change nothing.
func TestOIDCSignInSyncsGroupsAndName(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	conn := s.connect(t, organization, idp, nil)
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	verify(t, member.ID)
	group := func(externalID string) uuid.UUID {
		t.Helper()
		var ext, via any
		if externalID != "" {
			ext, via = externalID, "scim"
		}
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO organization.groups (organization_id, name, external_id, provisioned_via) VALUES ($1, $2, $3, $4) RETURNING id`,
			organization, dbtest.Unique("group"), ext, via).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	engineering, directory := group(""), group("00g-ext-1")
	if _, err := pool.Exec(ctx, `INSERT INTO organization.sso_group_mappings (organization_id, connection_id, idp_group, group_id) VALUES ($1, $2, 'Engineering', $3)`,
		organization, conn.ID, engineering); err != nil {
		t.Fatal(err)
	}
	memberships := func() map[uuid.UUID]bool {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT group_id FROM organization.group_members WHERE organization_id = $1 AND user_id = $2 AND source_connection_id = $3`,
			organization, member.ID, conn.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[uuid.UUID]bool{}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out[id] = true
		}
		return out
	}
	profile := func() (string, string) {
		t.Helper()
		var email, name string
		if err := pool.QueryRow(ctx, `SELECT email, COALESCE(display_name, '') FROM account.users WHERE id = $1`, member.ID).Scan(&email, &name); err != nil {
			t.Fatal(err)
		}
		return email, name
	}

	s.signIn(t, idp, conn.ID, as(idp, "entra-asha", member.Email, func(c jwt.MapClaims) {
		c["groups"] = []string{"engineering", "00G-EXT-1"}
		c["name"] = "Asha Rao"
	}))
	if got := memberships(); len(got) != 2 || !got[engineering] || !got[directory] {
		t.Errorf("memberships %v, want the mapped group and the SCIM group", got)
	}
	if _, name := profile(); name != "Asha Rao" {
		t.Errorf("display name %q, want the token's", name)
	}

	// The provider leaves the groups out for being too many: nothing changes.
	s.signIn(t, idp, conn.ID, as(idp, "entra-asha", member.Email, func(c jwt.MapClaims) {
		c["_claim_names"] = map[string]any{"groups": "src1"}
	}))
	if got := memberships(); len(got) != 2 {
		t.Errorf("memberships after withheld groups %v, want both kept", got)
	}

	// An address the provider says it hasn't verified isn't taken; one it
	// vouches for, on the organization's domain, is.
	unverified := dbtest.Unique("asha.u") + "@" + domain
	s.signIn(t, idp, conn.ID, as(idp, "entra-asha", unverified, func(c jwt.MapClaims) {
		c["email_verified"] = false
		c["groups"] = []string{"Engineering"}
		c["name"] = "Asha R."
	}))
	if email, name := profile(); email != member.Email || name != "Asha R." {
		t.Errorf("profile %q %q; want the address kept and the name changed", email, name)
	}
	if got := memberships(); len(got) != 1 || !got[engineering] {
		t.Errorf("memberships %v, want only the group the token still names", got)
	}
	moved := dbtest.Unique("asha.rao") + "@" + domain
	s.signIn(t, idp, conn.ID, as(idp, "entra-asha", moved, nil))
	if email, _ := profile(); email != moved {
		t.Errorf("address %q, want the one the provider vouches for, %q", email, moved)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'group.member_added' AND actor_type = 'oidc'`, organization); n != 2 {
		t.Errorf("%d memberships recorded as the sign-in's, want 2", n)
	}
}

// TestOIDCCodeOfAConnectionTurnedOffDoesNotExchange checks that a login code
// issued just before its connection was disabled, put back to draft or
// deleted signs nobody in, at the exchange or at the hosted session.
func TestOIDCCodeOfAConnectionTurnedOffDoesNotExchange(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newRP(t)
	idp := newFakeIdP(t)
	organization := dbtest.Organization(t)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	verify(t, member.ID)
	for _, tc := range []struct{ change, want string }{
		{`UPDATE organization.oidc_connections SET status = 'disabled' WHERE organization_id = $1 AND id = $2`, CodeConnectionDisabled},
		{`UPDATE organization.oidc_connections SET status = 'draft' WHERE organization_id = $1 AND id = $2`, CodeConnectionDraft},
		{`DELETE FROM organization.oidc_connections WHERE organization_id = $1 AND id = $2`, CodeLoginCodeInvalid},
	} {
		conn := s.connect(t, organization, idp, nil)
		exchange := loginCode(t, s.answer(t, idp, conn.ID, as(idp, "u-"+conn.ID.String(), member.Email, nil)))
		session := loginCode(t, s.answer(t, idp, conn.ID, as(idp, "u-"+conn.ID.String(), member.Email, nil)))
		if _, err := dbtest.Pool(t).Exec(ctx, tc.change, organization, conn.ID); err != nil {
			t.Fatal(err)
		}
		refused(t, tc.change+", then exchange its code", s.exchange(t, exchange), tc.want)
		refused(t, tc.change+", then trade its code for a hosted session",
			dbtest.Do(t, s.public, http.MethodPost, "/oidc-connections/session", map[string]string{"code": session}), tc.want)
	}
}
