//go:build integration

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// splitURL returns raw without its query, and the query.
func splitURL(t *testing.T, raw string) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	q := u.Query()
	u.RawQuery = ""
	return u.String(), q
}

// authorizeURL is an authorization request from clientID to testRedirect for
// openid, with state, a nonce and a fresh S256 challenge, params (pairs) set
// over those; it returns the challenge's verifier too.
func authorizeURL(t *testing.T, clientID string, params ...string) (string, string) {
	t.Helper()
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {testRedirect},
		"scope": {"openid"}, "state": {"st"}, "nonce": {"n-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	for i := 0; i+1 < len(params); i += 2 {
		q.Set(params[i], params[i+1])
	}
	return "/oauth/authorize?" + q.Encode(), verifier
}

// TestBrowserSignInToAnApplication checks the authorization code flow as a
// browser and an application run it: the hosted login shown the application,
// sign-in first, consent decided once by the browser that asked, the code
// redeemed for an ID token naming person, session and nonce, and userinfo.
func TestBrowserSignInToAnApplication(t *testing.T) {
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, p.svc, organization)
	cookie, sessionID := p.signIn(t, person.ID)
	otherBrowser, _ := p.signIn(t, person.ID)
	target, verifier := authorizeURL(t, client.ClientID, "scope", "openid email", "state", "st-1")

	var app struct {
		ClientName     string    `json:"client_name"`
		OrganizationID uuid.UUID `json:"organization_id"`
	}
	dbtest.Decode(t, browse(t, p.public, http.MethodGet, "/oauth/login-context?client_id="+client.ClientID, nil, nil), &app)
	if app.ClientName != client.Name || app.OrganizationID != organization {
		t.Errorf("login context %+v, want the application's name and organization", app)
	}
	if rec := browse(t, p.public, http.MethodGet, "/oauth/login-context?client_id=qci_unknown", nil, nil); !strings.Contains(rec.Body.String(), CodeClientNotFound) {
		t.Errorf("login context for an unknown client: %d %s", rec.Code, rec.Body.String())
	}
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, nil, nil))
	if to != loginBase+"/sign-in" || q.Get("return_to") != publicBase+target {
		t.Errorf("signed out: sent to %s to return to %q, want the hosted login and back to the request", to, q.Get("return_to"))
	}
	to, q = redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	requestID := q.Get("request_id")
	if to != loginBase+"/consent" || requestID == "" || len(q) != 1 {
		t.Fatalf("signed in without consent: sent to %s %v, want the consent screen with only a request id", to, q)
	}

	consent := "/oauth/authorize/request?request_id=" + requestID
	if rec := browse(t, p.public, http.MethodGet, consent, otherBrowser, nil); !strings.Contains(rec.Body.String(), CodeConsentRequestInvalid) {
		t.Errorf("another browser read the consent request: %d %s", rec.Code, rec.Body.String())
	}
	var shown struct {
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	dbtest.Decode(t, browse(t, p.public, http.MethodGet, consent, cookie, nil), &shown)
	if shown.ClientID != client.ClientID || shown.Scope != "openid email" {
		t.Errorf("consent screen shows %+v, want the stored request", shown)
	}

	decide := "/oauth/authorize/decision"
	approve := map[string]any{"request_id": requestID, "approve": true}
	if rec := browse(t, p.public, http.MethodPost, decide, otherBrowser, approve); !strings.Contains(rec.Body.String(), CodeConsentRequestInvalid) {
		t.Errorf("another browser decided the request: %d %s", rec.Code, rec.Body.String())
	}
	rec := browse(t, p.public, http.MethodPost, decide, cookie, approve)
	var decided struct {
		Redirect string `json:"redirect"`
	}
	dbtest.Decode(t, rec, &decided)
	to, q = splitURL(t, decided.Redirect)
	code := q.Get("code")
	if rec.Code != http.StatusOK || to != testRedirect || code == "" || q.Get("state") != "st-1" || q.Get("iss") != p.svc.issuer.JWTIssuer() {
		t.Fatalf("approve: %d %s, want the registered redirect with a code, the state and iss", rec.Code, decided.Redirect)
	}
	if rec := browse(t, p.public, http.MethodPost, decide, cookie, approve); !strings.Contains(rec.Body.String(), CodeConsentRequestInvalid) {
		t.Errorf("decide the request twice: %d %s", rec.Code, rec.Body.String())
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}}
	rec = postForm(t, p.public, "/oauth/token", form, client.ClientID, secret)
	var issued TokenResponse
	dbtest.Decode(t, rec, &issued)
	if rec.Code != http.StatusOK || issued.TokenType != "Bearer" || issued.Scope != "openid email" || issued.RefreshToken == "" || issued.ExpiresIn <= 0 {
		t.Fatalf("redeem the code: %d %s", rec.Code, rec.Body.String())
	}
	id, err := p.svc.issuer.VerifySigned(issued.IDToken)
	if err != nil {
		t.Fatalf("verify the ID token: %v", err)
	}
	for claim, want := range map[string]any{
		"iss": p.svc.issuer.JWTIssuer(), "aud": client.ClientID, "sub": person.ID.String(), "nonce": "n-1",
		"sid": sessionID.String(), "organization_id": organization.String(), "email": person.Email, "email_verified": false,
	} {
		if id[claim] != want {
			t.Errorf("ID token %s = %v, want %v", claim, id[claim], want)
		}
	}
	if _, ok := id["auth_time"].(float64); !ok {
		t.Errorf("ID token auth_time = %v, want when the person signed in", id["auth_time"])
	}
	if _, ok := id["updated_at"]; ok {
		t.Error("the ID token carries profile claims the request didn't ask for")
	}
	access, err := p.svc.issuer.VerifyAccessAnyAudience(issued.AccessToken)
	if err != nil || access.ClientID != client.ClientID || access.UserID != person.ID || access.Scope != "openid email" {
		t.Errorf("access token %+v, %v; want the person's, issued to the application, for the granted scope", access, err)
	}

	var info map[string]any
	rec = dbtest.Do(t, p.asApplication(t, issued.AccessToken), http.MethodGet, "/oauth/userinfo", nil)
	dbtest.Decode(t, rec, &info)
	if rec.Code != http.StatusOK || info["sub"] != person.ID.String() || info["email"] != person.Email || info["updated_at"] != nil {
		t.Errorf("userinfo: %d %v, want the person's email claims only", rec.Code, info)
	}
	noOpenID := dbtest.Principal(person.ID, organization)
	noOpenID.Scopes = []string{"email"}
	rec = dbtest.Do(t, dbtest.Serve(noOpenID, p.mount), http.MethodPost, "/oauth/userinfo", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Errorf("userinfo without openid: %d %q, want 403 insufficient_scope", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// openRegistration lets anyone register in any organization, with any password.
type openRegistration struct{}

func (openRegistration) SelfRegistrationEnabled(context.Context, uuid.UUID) (bool, error) {
	return true, nil
}

func (openRegistration) ValidateForOrganization(context.Context, uuid.UUID, string, string) error {
	return nil
}

// authorizeInBrowser runs an authorization request from clientID in the
// browser holding cookie, approving consent when asked, and returns where the
// browser is sent, with the query, and the request's PKCE verifier.
func (p *provider) authorizeInBrowser(t *testing.T, cookie *http.Cookie, clientID string) (string, url.Values, string) {
	t.Helper()
	target, verifier := authorizeURL(t, clientID)
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to == loginBase+"/consent" {
		var decided struct {
			Redirect string `json:"redirect"`
		}
		approve := map[string]any{"request_id": q.Get("request_id"), "approve": true}
		dbtest.Decode(t, browse(t, p.public, http.MethodPost, "/oauth/authorize/decision", cookie, approve), &decided)
		to, q = splitURL(t, decided.Redirect)
	}
	return to, q, verifier
}

// TestOrganizationsOwnAccountsSignInWithoutARole checks that the accounts an
// organization makes hold no role and still sign in to its applications and
// renew there, while a guest whose roles were removed and a suspended account
// of the organization's own are refused.
func TestOrganizationsOwnAccountsSignInWithoutARole(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	p := newProviderOver(t, func(d *authentication.Deps) { d.Registration = openRegistration{} })
	organization, elsewhere := dbtest.Organization(t), dbtest.Organization(t)
	client, secret := registerClient(t, p.svc, organization)

	_, registered, err := p.sessions.RegisterInOrganization(ctx, organization, dbtest.Unique("registered")+"@example.test", "Pw4!nKx7mQ2v", "", "192.0.2.1", "test")
	if err != nil || registered.RawCookie == "" {
		t.Fatalf("register: %+v, %v; want a hosted-login session", registered, err)
	}
	created, err := user.NewRepository(pool).CreateWithCredential(ctx, user.CreateInput{OrganizationID: organization, Email: dbtest.Unique("created") + "@example.test"}, "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	createdCookie, _ := p.signIn(t, created.ID)
	if n := dbtest.Count(t, `SELECT count(*) FROM rbac.user_roles WHERE organization_id = $1`, organization); n != 0 {
		t.Fatalf("the organization's accounts hold %d roles, want none", n)
	}
	for name, cookie := range map[string]*http.Cookie{
		"a self-registered account":           {Name: authentication.LoginSessionCookie, Value: registered.RawCookie},
		"an account an administrator created": createdCookie,
	} {
		to, q, verifier := p.authorizeInBrowser(t, cookie, client.ClientID)
		if to != testRedirect || q.Get("code") == "" {
			t.Errorf("%s signing in to the application: sent to %s %v, want a code", name, to, q)
			continue
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}}
		rec := postForm(t, p.public, "/oauth/token", form, client.ClientID, secret)
		var issued TokenResponse
		dbtest.Decode(t, rec, &issued)
		if rec.Code != http.StatusOK || issued.RefreshToken == "" {
			t.Errorf("%s redeeming the code: %d %s", name, rec.Code, rec.Body.String())
			continue
		}
		if out, err := p.svc.Introspect(ctx, client.ClientID, secret, issued.AccessToken, ""); err != nil || out["active"] != true {
			t.Errorf("%s's access token introspects %v, %v; want active", name, out, err)
		}
		if renewed, err := p.svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); err != nil || renewed.AccessToken == "" {
			t.Errorf("%s renewing: %+v, %v", name, renewed, err)
		}
	}

	formerGuest, suspended := dbtest.User(t, elsewhere, organization), dbtest.User(t, organization)
	guestTokens := redeemCode(t, p.svc, client, secret, formerGuest.ID, "")
	suspendedTokens := redeemCode(t, p.svc, client, secret, suspended.ID, "")
	guestCookie, _ := p.signIn(t, formerGuest.ID)
	suspendedCookie, _ := p.signIn(t, suspended.ID)
	if _, err := pool.Exec(ctx, `DELETE FROM rbac.user_roles WHERE user_id = $1 AND organization_id = $2`, formerGuest.ID, organization); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		account dbtest.Account
		cookie  *http.Cookie
		tokens  *TokenResponse
		renewal error
	}{
		{"a guest whose roles were removed", formerGuest, guestCookie, guestTokens, ErrUserOrganizationMismatch},
		{"a suspended account of the organization", suspended, suspendedCookie, suspendedTokens, errs.ErrAuthAccountSuspended},
	} {
		if to, q, _ := p.authorizeInBrowser(t, tc.cookie, client.ClientID); q.Get("code") != "" {
			t.Errorf("%s signed in to the application: sent to %s %v", tc.name, to, q)
		}
		_, challenge, _ := codes.URLToken()
		if _, _, err := p.svc.Authorize(ctx, tc.account.ID, client.ClientID, testRedirect, []string{"openid"}, "n-1", challenge, "S256"); !errors.Is(err, ErrUserOrganizationMismatch) {
			t.Errorf("%s authorized: %v, want %v", tc.name, err, ErrUserOrganizationMismatch)
		}
		if out, err := p.svc.Introspect(ctx, client.ClientID, secret, tc.tokens.AccessToken, ""); err != nil || out["active"] == true {
			t.Errorf("%s's access token introspects %v, %v; want inactive", tc.name, out, err)
		}
		if _, err := p.svc.RefreshToken(ctx, client.ClientID, secret, tc.tokens.RefreshToken, ""); !errors.Is(err, tc.renewal) {
			t.Errorf("%s renewing: %v, want %v", tc.name, err, tc.renewal)
		}
	}
}

// TestAuthorizeRemembersConsentAndHonoursPrompt checks that consent once given
// lets a later request straight back with a code, that prompt=consent asks
// again and an echoed value that differs from the stored request spends it,
// and that prompt=none and prompt=login are answered without a screen.
func TestAuthorizeRemembersConsentAndHonoursPrompt(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, _ := registerClient(t, p.svc, organization)
	cookie, _ := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, client.ClientID, []string{"openid", "email"}); err != nil {
		t.Fatalf("consent: %v", err)
	}

	target, _ := authorizeURL(t, client.ClientID, "scope", "openid email", "state", "st-2")
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != testRedirect || q.Get("code") == "" || q.Get("state") != "st-2" {
		t.Errorf("consented request: sent to %s %v, want the registered redirect with a code", to, q)
	}

	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		params []string
		want   string
	}{
		{"prompt=none signed out", nil, []string{"prompt", "none"}, "login_required"},
		{"prompt=none for a scope not consented", cookie, []string{"prompt", "none", "scope", "openid email profile"}, "consent_required"},
		{"prompt=none and prompt=login", cookie, []string{"prompt", "none login"}, "login_required"},
	} {
		target, _ := authorizeURL(t, client.ClientID, tc.params...)
		to, q := redirected(t, browse(t, p.public, http.MethodGet, target, tc.cookie, nil))
		if to != testRedirect || q.Get("error") != tc.want || q.Get("state") != "st" || q.Get("code") != "" {
			t.Errorf("%s: sent to %s %v, want error %s", tc.name, to, q, tc.want)
		}
	}
	target, _ = authorizeURL(t, client.ClientID, "prompt", "login")
	if to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil)); to != loginBase+"/sign-in" || q.Get("prompt") != "login" ||
		!strings.Contains(q.Get("return_to"), loginAfterParam+"=") {
		t.Errorf("prompt=login: sent to %s %v, want a fresh hosted sign-in that comes back", to, q)
	}
	// A marker added by hand doesn't stand for the forced sign-in.
	for _, forged := range []string{"0", strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)} {
		target, _ = authorizeURL(t, client.ClientID, "scope", "openid email", "prompt", "login", loginAfterParam, forged)
		if to, _ := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil)); to != loginBase+"/sign-in" {
			t.Errorf("prompt=login with login_after=%s added by hand: sent to %s, want the sign-in again", forged, to)
		}
	}

	target, _ = authorizeURL(t, client.ClientID, "scope", "openid email", "prompt", "consent")
	to, q = redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != loginBase+"/consent" {
		t.Fatalf("prompt=consent: sent to %s, want the consent screen", to)
	}
	tampered := map[string]any{"request_id": q.Get("request_id"), "approve": true, "redirect_uri": "https://evil.example.test/callback"}
	for _, body := range []map[string]any{tampered, {"request_id": q.Get("request_id"), "approve": true}} {
		if rec := browse(t, p.public, http.MethodPost, "/oauth/authorize/decision", cookie, body); !strings.Contains(rec.Body.String(), CodeConsentRequestInvalid) {
			t.Errorf("decide %v after a tampered decision: %d %s, want it refused", body, rec.Code, rec.Body.String())
		}
	}
}

// TestAuthorizeAnswersOnlyRegisteredRedirects checks that the authorization
// endpoint sends the browser only to a redirect_uri registered exactly: a near
// miss is shown the error here, while a refused request naming the registered
// address goes back to it with the OAuth error, the state and iss.
func TestAuthorizeAnswersOnlyRegisteredRedirects(t *testing.T) {
	p := newProvider(t)
	organization, otherOrganization := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	outsider := dbtest.User(t, otherOrganization, otherOrganization)
	client, _ := registerClient(t, p.svc, organization)
	cookie, _ := p.signIn(t, person.ID)
	outsiderCookie, _ := p.signIn(t, outsider.ID)

	for _, tc := range []struct{ clientID, redirect string }{
		{client.ClientID, ""},
		{client.ClientID, testRedirect + "/"},
		{client.ClientID, testRedirect + "?next=/admin"},
		{client.ClientID, testRedirect + "#frag"},
		{client.ClientID, "HTTPS://APP.EXAMPLE.TEST/callback"},
		{client.ClientID, "https://app.example.test/callback/../evil"},
		{client.ClientID, "https://app.example.test.evil.test/callback"},
		{client.ClientID, "http://app.example.test/callback"},
		{"qci_unknown", testRedirect},
	} {
		target, _ := authorizeURL(t, tc.clientID, "redirect_uri", tc.redirect)
		rec := browse(t, p.public, http.MethodGet, target, cookie, nil)
		if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), ErrRedirectURINotRegistered.Code) {
			t.Errorf("client %s redirect_uri %q: %d to %q, want the error shown here", tc.clientID, tc.redirect, rec.Code, rec.Header().Get("Location"))
		}
	}

	for _, tc := range []struct {
		name   string
		params []string
		cookie *http.Cookie
		want   string
	}{
		{"an implicit-flow request", []string{"response_type", "token"}, cookie, "unsupported_response_type"},
		{"no response_type", []string{"response_type", ""}, cookie, "invalid_request"},
		{"a request object", []string{"request", "eyJhbGciOiJub25lIn0.e30."}, cookie, "request_not_supported"},
		{"a fragment response mode", []string{"response_mode", "fragment"}, cookie, "invalid_request"},
		{"no PKCE challenge", []string{"code_challenge", ""}, cookie, "invalid_request"},
		{"a plain PKCE challenge", []string{"code_challenge_method", "plain"}, cookie, "invalid_request"},
		{"an unregistered resource", []string{"resource", "https://api.example.test"}, cookie, "invalid_target"},
		{"a person of another organization", nil, outsiderCookie, "access_denied"},
	} {
		target, _ := authorizeURL(t, client.ClientID, append(tc.params, "state", "s-1")...)
		to, q := redirected(t, browse(t, p.public, http.MethodGet, target, tc.cookie, nil))
		if to != testRedirect || q.Get("error") != tc.want || q.Get("state") != "s-1" || q.Get("iss") != p.svc.issuer.JWTIssuer() || q.Get("code") != "" {
			t.Errorf("%s: sent to %s %v, want error %s with the state and iss", tc.name, to, q, tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_consent_requests WHERE client_id = $1`, client.ClientID); n != 0 {
		t.Errorf("refused requests stored %d consent requests, want none", n)
	}
}

// TestCodeFlowWithPKCENeedsNoNonce checks that an OpenID request with a PKCE
// challenge and no nonce, as Auth.js sends it, gets a code that redeems for an
// ID token without a nonce claim.
func TestCodeFlowWithPKCENeedsNoNonce(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClient(t, p.svc, organization)
	cookie, _ := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, client.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}

	target, verifier := authorizeURL(t, client.ClientID, "nonce", "")
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != testRedirect || q.Get("code") == "" || q.Get("error") != "" {
		t.Fatalf("authorize without a nonce: sent to %s %v, want a code", to, q)
	}
	issued, err := p.svc.ExchangeCode(ctx, client.ClientID, secret, q.Get("code"), testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem the code: %v", err)
	}
	id, err := p.svc.issuer.VerifySigned(issued.IDToken)
	if err != nil {
		t.Fatalf("verify the ID token: %v", err)
	}
	if _, ok := id["nonce"]; ok || id["sub"] != person.ID.String() {
		t.Errorf("ID token %v, want the person's without a nonce", id)
	}
}

// TestLoopbackRedirectOnAnyPort checks that a native application registered
// with a loopback redirect gets its code on whatever port it asks for (RFC 8252
// §7.3) and redeems it only with that same redirect_uri, while another path or
// host on the loopback is still refused.
func TestLoopbackRedirectOnAnyPort(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	native, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Type: "public", RedirectURIs: []string{"http://127.0.0.1/callback"}})
	cookie, _ := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, native.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}

	const asked = "http://127.0.0.1:49152/callback"
	target, verifier := authorizeURL(t, native.ClientID, "redirect_uri", asked)
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != asked || q.Get("code") == "" {
		t.Fatalf("authorize on port 49152: sent to %s %v, want a code at that port", to, q)
	}
	if _, err := p.svc.ExchangeCode(ctx, native.ClientID, "", q.Get("code"), "http://127.0.0.1:49153/callback", verifier, ""); !errors.Is(err, ErrRedirectURIMismatch) {
		t.Errorf("redeem at another port: %v, want %v", err, ErrRedirectURIMismatch)
	}
	if issued, err := p.svc.ExchangeCode(ctx, native.ClientID, "", q.Get("code"), asked, verifier, ""); err != nil || issued.AccessToken == "" {
		t.Errorf("redeem at the port it asked for: %+v, %v", issued, err)
	}

	for _, redirect := range []string{"http://127.0.0.1:49152/other", "http://127.0.0.2:49152/callback", "http://localhost:49152/callback"} {
		target, _ := authorizeURL(t, native.ClientID, "redirect_uri", redirect)
		rec := browse(t, p.public, http.MethodGet, target, cookie, nil)
		if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), ErrRedirectURINotRegistered.Code) {
			t.Errorf("redirect_uri %q: %d to %q, want the error shown here", redirect, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// TestOfflineAccessControlsRefreshTokens checks that offline_access is
// accepted from any application registered for refresh, that one which didn't
// register it gets a refresh token with every grant as before, that one which
// did gets one only when it asks, on the code and device flows alike, and that
// an application not registered for refresh is refused the scope.
func TestOfflineAccessControlsRefreshTokens(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	standard, standardSecret := registerClient(t, p.svc, organization)
	optedIn, optedInSecret := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, Scopes: []string{"openid", "email", "offline_access"}})
	codeOnly, _ := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization, GrantTypes: []string{"authorization_code"}})
	redeem := func(c *Client, secret string, scopes ...string) *TokenResponse {
		t.Helper()
		verifier, challenge, _ := codes.URLToken()
		code, _, err := p.svc.Authorize(ctx, person.ID, c.ClientID, testRedirect, scopes, "", challenge, "S256")
		if err != nil {
			t.Fatalf("authorize %v: %v", scopes, err)
		}
		issued, err := p.svc.ExchangeCode(ctx, c.ClientID, secret, code, testRedirect, verifier, "")
		if err != nil {
			t.Fatalf("redeem %v: %v", scopes, err)
		}
		return issued
	}

	for _, tc := range []struct {
		name    string
		client  *Client
		secret  string
		scopes  []string
		refresh bool
	}{
		{"an application that didn't register offline_access, asking for it", standard, standardSecret, []string{"openid", "offline_access"}, true},
		{"an application that didn't register offline_access, not asking", standard, standardSecret, []string{"openid"}, true},
		{"an application that registered offline_access, asking for it", optedIn, optedInSecret, []string{"openid", "offline_access"}, true},
		{"an application that registered offline_access, not asking", optedIn, optedInSecret, []string{"openid"}, false},
	} {
		issued := redeem(tc.client, tc.secret, tc.scopes...)
		if (issued.RefreshToken != "") != tc.refresh || issued.Scope != strings.Join(tc.scopes, " ") {
			t.Errorf("%s: refresh token %q, scope %q; want one %v, scope %v", tc.name, issued.RefreshToken, issued.Scope, tc.refresh, tc.scopes)
			continue
		}
		if tc.refresh {
			if renewed, err := p.svc.RefreshToken(ctx, tc.client.ClientID, tc.secret, issued.RefreshToken, ""); err != nil || renewed.RefreshToken == "" || renewed.Scope != issued.Scope {
				t.Errorf("%s: renew %+v, %v; want a new pair for the same scope", tc.name, renewed, err)
			}
		}
	}
	_, challenge, _ := codes.URLToken()
	if _, _, err := p.svc.Authorize(ctx, person.ID, codeOnly.ClientID, testRedirect, []string{"openid", "offline_access"}, "", challenge, "S256"); !errors.Is(err, ErrScopeNotPermitted) {
		t.Errorf("offline_access from an application not registered for refresh: %v, want %v", err, ErrScopeNotPermitted)
	}

	device, _ := registerClientWith(t, p.svc, CreateClientInput{
		OrganizationID: organization, Type: "public", GrantTypes: []string{grantTypeDeviceCode, "refresh_token"}, Scopes: []string{"openid", "offline_access"},
	})
	cookie, _ := p.signIn(t, person.ID)
	for scope, refresh := range map[string]bool{"openid": false, "openid offline_access": true, "": true} {
		rec := postForm(t, p.public, "/oauth/device_authorization", url.Values{"client_id": {device.ClientID}, "scope": {scope}}, "", "")
		var started DeviceAuthResponse
		dbtest.Decode(t, rec, &started)
		if rec := browse(t, p.public, http.MethodPost, "/oauth/device/decision", cookie, map[string]any{"user_code": started.UserCode, "approve": true}); rec.Code != http.StatusOK {
			t.Fatalf("device scope %q: approve: %d %s", scope, rec.Code, rec.Body.String())
		}
		rec = postForm(t, p.public, "/oauth/token", url.Values{"grant_type": {grantTypeDeviceCode}, "client_id": {device.ClientID}, "device_code": {started.DeviceCode}}, "", "")
		var issued TokenResponse
		dbtest.Decode(t, rec, &issued)
		if rec.Code != http.StatusOK || (issued.RefreshToken != "") != refresh {
			t.Errorf("device scope %q: %d %s, want a refresh token %v", scope, rec.Code, rec.Body.String(), refresh)
		}
	}
}

// TestAuthorizeRefusesScopesBeforeConsent checks that a request for a scope
// the application may not have goes back to it as invalid_scope, before the
// person is asked to consent to it.
func TestAuthorizeRefusesScopesBeforeConsent(t *testing.T) {
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, _ := registerClient(t, p.svc, organization)
	cookie, _ := p.signIn(t, person.ID)

	target, _ := authorizeURL(t, client.ClientID, "scope", "openid admin")
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != testRedirect || q.Get("error") != "invalid_scope" {
		t.Errorf("a scope the application may not have: sent to %s %v, want invalid_scope", to, q)
	}
}
