//go:build integration

package oidcsso

// Database tests for sign-in through an organization's OpenID Connect
// provider: a fake provider (fakeidp_test.go) answers the authorization
// request /oidc-connections/{id}/login sends it, and the callback and
// exchange turn its ID token into a session.

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	testAppBase    = "https://console.example.test"           // where a sign-in hands its code
	testPublicBase = "https://id.example.test"                // this API's public origin
	callbackStart  = testAppBase + "/sso/callback#oidc_code=" // a completed sign-in's redirect, before the code
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// rp is the relying party: the service, its routes and the cookies of the one
// browser signing in.
type rp struct {
	svc     *Service
	handler *Handler
	public  chi.Router
	browser []*http.Cookie
}

func newRP(t *testing.T) *rp {
	t.Helper()
	pool := dbtest.Pool(t)
	svc := NewService(pool, auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t)), testAppBase, egress.DevelopmentPolicy())
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetCipher(box)
	h := &Handler{Service: svc, PublicBaseURL: testPublicBase}
	public := chi.NewRouter()
	h.MountPublic(public)
	return &rp{svc: svc, handler: h, public: public}
}

// send serves req from the browser, keeping the cookies it is given.
func (s *rp) send(req *http.Request) *httptest.ResponseRecorder {
	for _, c := range s.browser {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.public.ServeHTTP(rec, req)
	for _, set := range rec.Result().Cookies() {
		kept := s.browser[:0]
		for _, c := range s.browser {
			if c.Name != set.Name {
				kept = append(kept, c)
			}
		}
		s.browser = kept
		if set.MaxAge >= 0 {
			s.browser = append(s.browser, set)
		}
	}
	return rec
}

// admin returns organization's administration routes as a new admin of it.
func (s *rp) admin(t *testing.T, organization uuid.UUID) http.Handler {
	t.Helper()
	return dbtest.Serve(dbtest.Principal(dbtest.User(t, organization, organization).ID, organization), s.handler.Mount)
}

// connect has organization's admin create an active connection to idp, with change
// applied to the request.
func (s *rp) connect(t *testing.T, organization uuid.UUID, idp *fakeIdP, change map[string]any) Connection {
	t.Helper()
	body := map[string]any{
		"name": "Entra", "issuer": idp.URL, "client_id": testClientID, "client_secret": testClientSecret,
		"status": "active", "claim_mapping": map[string]any{"groups": "groups"},
	}
	for k, v := range change {
		body[k] = v
	}
	rec := dbtest.Do(t, s.admin(t, organization), http.MethodPost, "/tenants/"+organization.String()+"/oidc-connections", body)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create the connection: %d %s", rec.Code, rec.Body.String())
	}
	return conn
}

// begin starts a sign-in through connID as the browser and returns the
// provider URL it is sent to.
func (s *rp) begin(t *testing.T, connID uuid.UUID) string {
	t.Helper()
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+connID.String()+"/login", nil))
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, testAuthorizeBase+"?") {
		t.Fatalf("login: %d %s %s; want a redirect to the provider", rec.Code, location, rec.Body.String())
	}
	u, _ := url.Parse(location)
	if got := u.Query().Get("redirect_uri"); got != testPublicBase+"/v1/oidc-connections/"+connID.String()+"/callback" {
		t.Fatalf("redirect_uri %q; want this connection's callback", got)
	}
	return location
}

// callback brings the provider's answer to the sign-in authURL began back to
// connID's callback as the browser, with extra query parameters.
func (s *rp) callback(t *testing.T, connID uuid.UUID, authURL, code string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(authURL)
	q := url.Values{"state": {u.Query().Get("state")}, "code": {code}}
	for k, v := range extra {
		q[k] = v
	}
	return s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+connID.String()+"/callback?"+q.Encode(), nil))
}

// answer runs a sign-in through conn, the provider issuing the token claims
// returns, and returns the callback's response.
func (s *rp) answer(t *testing.T, idp *fakeIdP, connID uuid.UUID, claims func(nonce string) jwt.MapClaims) *httptest.ResponseRecorder {
	t.Helper()
	authURL := s.begin(t, connID)
	code := "code-" + uuid.NewString()
	idp.expect(t, authURL, code, claims, nil, "")
	return s.callback(t, connID, authURL, code, nil)
}

// exchange trades a one-time login code.
func (s *rp) exchange(t *testing.T, code string) *httptest.ResponseRecorder {
	t.Helper()
	return dbtest.Do(t, s.public, http.MethodPost, "/oidc-connections/exchange", map[string]string{"code": code})
}

// signIn runs a whole sign-in and returns the token pair it buys.
func (s *rp) signIn(t *testing.T, idp *fakeIdP, connID uuid.UUID, claims func(nonce string) jwt.MapClaims) auth.TokenPair {
	t.Helper()
	rec := s.exchange(t, loginCode(t, s.answer(t, idp, connID, claims)))
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	return pair
}

// loginCode returns the one-time code a completed sign-in hands the console.
func loginCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(location, callbackStart) || len(location) == len(callbackStart) {
		t.Fatalf("callback: %d %s %s; want the console's callback with a code", rec.Code, location, rec.Body.String())
	}
	return strings.TrimPrefix(location, callbackStart)
}

// refused fails unless rec answers with code.
func refused(t *testing.T, what string, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if rec.Code/100 != 4 && rec.Code/100 != 5 || !strings.Contains(rec.Body.String(), code) {
		t.Errorf("%s: %d %s %s, want %s", what, rec.Code, rec.Header().Get("Location"), rec.Body.String(), code)
	}
}

// as returns claims for the provider's correct token, changed by change.
func as(idp *fakeIdP, sub, email string, change func(jwt.MapClaims)) func(string) jwt.MapClaims {
	return func(nonce string) jwt.MapClaims {
		claims := idp.claimsFor(nonce, sub, email)
		if change != nil {
			change(claims)
		}
		return claims
	}
}

func verify(t *testing.T, userID uuid.UUID) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE account.users SET email_verified_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
}

func sessionOrganization(t *testing.T, sessionID uuid.UUID) uuid.UUID {
	t.Helper()
	var organization uuid.UUID
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT organization_id FROM auth.sessions WHERE id = $1`, sessionID).Scan(&organization); err != nil {
		t.Fatalf("session %s: %v", sessionID, err)
	}
	return organization
}

// failures counts the failed sign-ins recorded in organization for reason.
func failures(t *testing.T, organization uuid.UUID, reason string) int {
	t.Helper()
	return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_failed'
		AND metadata->>'method' = 'oidc' AND metadata->>'reason' = $2`, organization, reason)
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
	if replay := s.callback(t, conn.ID, authURL, "code-1", nil); !strings.Contains(replay.Body.String(), errs.CodeOIDCSSOStateInvalid) {
		t.Errorf("the same answer brought back again: %d %s, want %s", replay.Code, replay.Body.String(), errs.CodeOIDCSSOStateInvalid)
	}
	if n := failures(t, organization, errs.CodeOIDCSSOStateInvalid); n != 1 {
		t.Errorf("%d replays recorded as failed sign-ins, want 1", n)
	}
	rec := s.exchange(t, code)
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.UserID != member.ID || sessionOrganization(t, pair.SessionID) != organization {
		t.Fatalf("exchange: %d %s; want a session for the member in the organisation", rec.Code, rec.Body.String())
	}
	refused(t, "a one-time code used again", s.exchange(t, code), errs.CodeOIDCSSOLoginCodeUsed)
	refused(t, "an unknown code", s.exchange(t, "not-a-code"), errs.CodeOIDCSSOLoginCodeInvalid)
	refused(t, "no code", s.exchange(t, ""), errs.CodeOIDCSSOLoginCodeRequired)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id = $2 AND provider = 'oidc'
		AND connection_id = $3 AND subject = $4 AND metadata->'groups' = '["engineering", "oncall"]'::jsonb`,
		member.ID, organization, conn.ID, idp.URL+"#entra-asha"); n != 1 {
		t.Errorf("%d identities linked for the member to the connection with their groups, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.login_succeeded' AND metadata->>'method' = 'oidc'`, organization); n != 1 {
		t.Errorf("%d OpenID Connect sign-ins recorded, want 1", n)
	}
	var got Connection
	dbtest.Decode(t, dbtest.Do(t, s.admin(t, organization), http.MethodGet, "/tenants/"+organization.String()+"/oidc-connections/"+conn.ID.String(), nil), &got)
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
		t.Errorf("the newcomer was not provisioned into the organisation, verified and named")
	}

	// A draft connection signs nobody in.
	draft := s.connect(t, organization, idp, map[string]any{"status": "draft"})
	rec = s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+draft.ID.String()+"/login", nil))
	refused(t, "a draft connection's sign-in", rec, errs.CodeOIDCSSOConnectionDraft)
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
		refused(t, "a token "+name, run(t), errs.CodeOIDCSSOIDTokenInvalid)
	}
	if n := failures(t, organization, errs.CodeOIDCSSOIDTokenInvalid); n != len(bad) {
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
	refused(t, "the provider's refusal", s.callback(t, conn.ID, authURL, "", url.Values{"error": {"access_denied"}}), errs.CodeOIDCSSOProviderRefused)
	refused(t, "the refused sign-in again", s.callback(t, conn.ID, authURL, "code", nil), errs.CodeOIDCSSOStateInvalid)
	// A code the provider won't redeem fails the exchange.
	refused(t, "a code the provider doesn't know", s.callback(t, conn.ID, s.begin(t, conn.ID), "unknown-code", nil), errs.CodeOIDCSSOTokenExchangeFailed)
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
	refused(t, "the callback in another browser", s.callback(t, conn.ID, authURL, "code-1", nil), errs.CodeOIDCSSOOtherBrowser)
	s.browser = held
	refused(t, "the spent sign-in in its own browser", s.callback(t, conn.ID, authURL, "code-1", nil), errs.CodeOIDCSSOStateInvalid)

	// One connection's sign-in doesn't complete at another's callback.
	other := s.connect(t, organization, idp, nil)
	authURL = s.begin(t, conn.ID)
	idp.expect(t, authURL, "code-2", as(idp, "u-1", email, nil), nil, "")
	refused(t, "the sign-in at another connection's callback", s.callback(t, other.ID, authURL, "code-2", nil), errs.CodeOIDCSSOStateInvalid)
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
		s.answer(t, idp, conn.ID, as(idp, "u-unverified", dbtest.Unique("x")+"@example.test", nil)), errs.CodeOIDCSSOEmailDomainUnverified)
	foreign := dbtest.UserAt(t, dbtest.Unique("y")+"@"+othersDomain, other, other)
	verify(t, foreign.ID)
	refused(t, "another organisation's domain",
		s.answer(t, idp, conn.ID, as(idp, "u-foreign", foreign.Email, nil)), errs.CodeOIDCSSOEmailDomainUnverified)
	refused(t, "an address the provider calls unverified",
		s.answer(t, idp, conn.ID, as(idp, "u-false", dbtest.Unique("z")+"@"+domain, func(c jwt.MapClaims) { c["email_verified"] = false })),
		errs.CodeOIDCSSOEmailUnverified)
	unverified := dbtest.UserAt(t, dbtest.Unique("squatter")+"@"+domain, organization, organization)
	refused(t, "an account that never proved its address",
		s.answer(t, idp, conn.ID, as(idp, "u-squatter", unverified.Email, nil)), errs.CodeOIDCSSOAccountUnverified)
	owner := dbtest.UserAt(t, dbtest.Unique("owner")+"@"+domain, organization)
	verify(t, owner.ID)
	dbtest.Assign(t, owner.ID, organization, dbtest.Role(t, organization, "connection.write"))
	refused(t, "an administrator", s.answer(t, idp, conn.ID, as(idp, "u-owner", owner.Email, nil)), errs.CodeOIDCSSOAccountAdministers)
	guest := dbtest.UserAt(t, dbtest.Unique("guest")+"@"+domain, other, organization)
	verify(t, guest.ID)
	refused(t, "a guest whose home is elsewhere", s.answer(t, idp, conn.ID, as(idp, "u-guest", guest.Email, nil)), errs.CodeOIDCSSOUserOrganizationMismatch)
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
	if n := failures(t, organization, errs.CodeOIDCSSOAccountAdministers); n != 1 {
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
	refused(t, "a tenant the connection doesn't list", s.answer(t, idp, conn.ID, as(idp, "u-1", member.Email, from(theirs))), errs.CodeOIDCSSOIDTokenInvalid)

	open := s.connect(t, organization, idp, map[string]any{"issuer": idp.URL + "/organizations/v2.0", "discovery_url": discovery})
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+open.ID.String()+"/login", nil))
	refused(t, "a connection listing no tenants of a multi-tenant provider", rec, errs.CodeOIDCSSOMisconfigured)
}

// denyPlan is a plan without single sign-on.
type denyPlan struct{}

func (denyPlan) FeatureAllowed(context.Context, uuid.UUID, string) (bool, error) { return false, nil }

// TestOIDCConnectionsOverHTTP checks that an organization creates, lists,
// reads, changes and deletes its connections, refusing invalid input, never
// returning or storing the client secret in the clear, and auditing each
// change; that another organization can neither see nor change them; and that
// a plan without single sign-on can't create one.
func TestOIDCConnectionsOverHTTP(t *testing.T) {
	s := newRP(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), s.handler.Mount)
	asOther := dbtest.Serve(dbtest.Principal(dbtest.User(t, other, other).ID, other), s.handler.Mount)
	base := "/tenants/" + organization.String() + "/oidc-connections"
	connection := map[string]any{
		"name": " Okta ", "issuer": " https://acme.okta.example.test ", "client_id": "okta-client", "client_secret": "okta-secret-value",
		"scopes": []string{"email", "groups"},
	}
	with := func(change map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range connection {
			out[k] = v
		}
		for k, v := range change {
			out[k] = v
		}
		return out
	}
	for code, change := range map[string]map[string]any{
		errs.CodeOIDCSSOFieldsRequired:    {"client_secret": ""},
		errs.CodeOIDCSSOIssuerInvalid:     {"issuer": "https://idp.example.test/?tenant=1"},
		errs.CodeOIDCSSOTenantIDsRequired: {"issuer": "https://login.microsoftonline.com/common/v2.0"},
		errs.CodeOIDCSSOStatusInvalid:     {"status": "enabled"},
	} {
		refused(t, "create with "+code, dbtest.Do(t, asAdmin, http.MethodPost, base, with(change)), code)
	}
	rec := dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	var conn Connection
	dbtest.Decode(t, rec, &conn)
	if rec.Code != http.StatusCreated || conn.Name != "Okta" || conn.Issuer != "https://acme.okta.example.test" || conn.Status != "draft" ||
		conn.OrganizationID != organization || strings.Join(conn.Scopes, " ") != "openid email groups" || conn.ClaimMapping.Email != "email" ||
		conn.RedirectURI != testPublicBase+"/v1/oidc-connections/"+conn.ID.String()+"/callback" {
		t.Fatalf("create: %d %s; want a trimmed draft in the organisation with its redirect URI", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "okta-secret-value") {
		t.Error("the client secret was returned")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.oidc_connections WHERE id = $1
		AND position(convert_to('okta-secret-value', 'UTF8') IN client_secret_ct) = 0`, conn.ID); n != 1 {
		t.Error("the client secret is stored in the clear")
	}
	if rec := dbtest.Do(t, asOther, http.MethodPost, "/tenants/"+other.String()+"/oidc-connections", connection); rec.Code != http.StatusCreated {
		t.Fatalf("another organisation's create: %d %s", rec.Code, rec.Body.String())
	}
	if ids := dbtest.IDs(t, dbtest.Do(t, asAdmin, http.MethodGet, base, nil)); len(ids) != 1 || ids[0] != conn.ID {
		t.Errorf("list %v, want only the organisation's own %s", ids, conn.ID)
	}
	path := base + "/" + conn.ID.String()
	refused(t, "a malformed ID", dbtest.Do(t, asAdmin, http.MethodGet, base+"/not-a-uuid", nil), errs.CodeOIDCSSOIDInvalid)

	for code, change := range map[string]map[string]any{
		errs.CodeOIDCSSOStatusInvalid:     {"status": "retired"},
		errs.CodeOIDCSSOIssuerInvalid:     {"issuer": "javascript:alert(1)"},
		errs.CodeOIDCSSOClaimInvalid:      {"claim_mapping": map[string]any{"email": ""}},
		errs.CodeOIDCSSOTenantIDsRequired: {"issuer": "https://login.microsoftonline.com/organizations/v2.0"},
	} {
		refused(t, "update with "+code, dbtest.Do(t, asAdmin, http.MethodPatch, path, change), code)
	}
	rec = dbtest.Do(t, asAdmin, http.MethodPatch, path, map[string]any{
		"name": "Head office", "status": "active", "client_secret": "rotated-secret", "claim_mapping": map[string]any{"email": "upn", "groups": "roles"},
	})
	var updated Connection
	dbtest.Decode(t, rec, &updated)
	if rec.Code != http.StatusOK || updated.Name != "Head office" || updated.Status != "active" ||
		updated.ClaimMapping.Email != "upn" || updated.ClaimMapping.Groups != "roles" || updated.ClaimMapping.Name != "name" {
		t.Errorf("rename, activate and remap: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, base+"/"+uuid.NewString(), map[string]any{"name": "Nobody"}); rec.Code != http.StatusNotFound {
		t.Errorf("update an unknown connection: %d, want 404", rec.Code)
	}

	otherPath := "/tenants/" + other.String() + "/oidc-connections/" + conn.ID.String()
	for _, method := range []string{http.MethodGet, http.MethodPatch, http.MethodDelete} {
		if rec := dbtest.Do(t, asOther, method, otherPath, map[string]any{"name": "Taken"}); rec.Code != http.StatusNotFound {
			t.Errorf("another organisation %s on the connection: %d, want 404", method, rec.Code)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if rec := dbtest.Do(t, asOther, method, base, connection); rec.Code != http.StatusForbidden {
			t.Errorf("another organisation %s on this organisation's connections: %d, want 403", method, rec.Code)
		}
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
		t.Errorf("get a deleted connection: %d, want 404", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2
		AND action LIKE 'oidc_connection.%' AND actor_user_id = $3`, organization, conn.ID, admin.ID); n != 3 {
		t.Errorf("%d connection changes recorded, want created, updated and deleted", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND resource_id = $2
		AND action = 'oidc_connection.updated' AND metadata->'fields' ? 'client_secret'`, organization, conn.ID); n != 1 {
		t.Error("the update's record doesn't name the replaced secret")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.oidc_connections WHERE organization_id = $1`, other); n != 1 {
		t.Errorf("another organisation's connections: %d, want its one untouched", n)
	}

	s.svc.SetPlanGate(denyPlan{})
	rec = dbtest.Do(t, asAdmin, http.MethodPost, base, connection)
	if rec.Code != http.StatusPaymentRequired || !strings.Contains(rec.Body.String(), errs.CodeUpgradeRequired) {
		t.Errorf("create on a plan without single sign-on: %d %s, want 402 %s", rec.Code, rec.Body.String(), errs.CodeUpgradeRequired)
	}
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

	refused(t, "a newcomer with provisioning off", s.answer(t, idp, conn.ID, as(idp, "u-new", newcomer, nil)), errs.CodeOIDCSSOJITNotAllowed)
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
	s.svc.SetPlanGate(denyPlan{})
	refused(t, "the answer after the plan lapsed", s.callback(t, conn.ID, authURL, "code-1", nil), errs.CodeUpgradeRequired)
	rec := s.send(httptest.NewRequestWithContext(dbtest.Context(t), http.MethodGet, "/oidc-connections/"+conn.ID.String()+"/login", nil))
	refused(t, "a sign-in started on a plan without single sign-on", rec, errs.CodeUpgradeRequired)
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE email = $1`, email); n != 0 {
		t.Errorf("a sign-in refused for the plan provisioned %d accounts", n)
	}
}

// expect makes the token endpoint redeem code, for the sign-in authURL began,
// with an ID token: the one claims returns for the nonce authURL carries,
// signed as sign would.
func (p *fakeIdP) expect(t *testing.T, authURL, code string, claims func(nonce string) jwt.MapClaims, signer crypto.Signer, kid string) {
	t.Helper()
	u, err := url.Parse(authURL)
	q := u.Query()
	if err != nil || !strings.HasPrefix(authURL, testAuthorizeBase+"?") || q.Get("code_challenge_method") != "S256" ||
		q.Get("client_id") != testClientID || q.Get("response_type") != "code" || q.Get("nonce") == "" || q.Get("state") == "" ||
		!strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		t.Fatalf("authorization URL %q; want the provider's, with PKCE, a state, a nonce and openid", authURL)
	}
	token := p.sign(t, claims(q.Get("nonce")), signer, kid)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pending[code] = pendingCode{challenge: q.Get("code_challenge"), redirectURI: q.Get("redirect_uri"), token: token}
}
