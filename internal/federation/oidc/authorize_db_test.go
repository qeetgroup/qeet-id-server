//go:build integration

package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	loginBase  = "https://login.example.test"
	publicBase = "https://id.example.test"
)

// provider is the OpenID provider as browsers and applications reach it: the
// service, a real hosted-login session service, the public routes and the
// authenticated ones.
type provider struct {
	svc      *Service
	sessions *auth.Service
	public   http.Handler
	mount    func(chi.Router)
}

// newProvider returns the provider wired as production wires it, sign-out
// notices included.
func newProvider(t *testing.T) *provider {
	t.Helper()
	pool := dbtest.Pool(t)
	issuer := dbtest.Issuer(t)
	svc := NewService(pool, issuer)
	sessions := auth.NewService(pool, user.NewRepository(pool), issuer)
	sessions.SetSignOutNotifier(svc)
	h := &Handler{Service: svc, Sessions: sessions, LoginBaseURL: loginBase, PublicBaseURL: publicBase}
	public := chi.NewRouter()
	h.MountPublic(public)
	h.MountBrowser(public)
	h.MountToken(public)
	return &provider{svc: svc, sessions: sessions, public: public, mount: h.Mount}
}

// signIn opens a hosted-login session for userID and returns the browser's
// cookie and the session's id.
func (p *provider) signIn(t *testing.T, userID uuid.UUID) (*http.Cookie, uuid.UUID) {
	t.Helper()
	ctx := dbtest.Context(t)
	raw, err := p.sessions.CreateLoginSession(ctx, userID, "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	sessionID, _, err := p.sessions.ResolveLoginSessionWithID(ctx, raw)
	if err != nil {
		t.Fatalf("resolve the session: %v", err)
	}
	return &http.Cookie{Name: auth.LoginSessionCookie, Value: raw}, sessionID
}

// asApplication serves the authenticated routes to the bearer of an access
// token issued to an application, as the API's token middleware would.
func (p *provider) asApplication(t *testing.T, accessToken string) http.Handler {
	t.Helper()
	claims, err := p.svc.issuer.VerifyAccessAnyAudience(accessToken)
	if err != nil {
		t.Fatalf("verify the access token: %v", err)
	}
	principal := dbtest.Principal(claims.UserID, claims.TenantID)
	principal.Scopes = strings.Fields(claims.Scope)
	return dbtest.Serve(principal, p.mount)
}

// browse sends a request as a browser holding cookie (nil for none), with
// body (when not nil) as JSON.
func browse(t *testing.T, h http.Handler, method, target string, cookie *http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatalf("encode the body: %v", err)
		}
	}
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// postForm posts form to path, with Basic credentials when user is not
// empty.
func postForm(t *testing.T, h http.Handler, path string, form url.Values, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(dbtest.Context(t), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// redirected returns where a 302 sends the browser, without the query, and
// the query; any other answer fails t.
func redirected(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("want a redirect, got %d %s", rec.Code, rec.Body.String())
	}
	return splitURL(t, rec.Header().Get("Location"))
}

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
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, p.svc, tenant)
	cookie, sessionID := p.signIn(t, person.ID)
	otherBrowser, _ := p.signIn(t, person.ID)
	target, verifier := authorizeURL(t, client.ClientID, "scope", "openid email", "state", "st-1")

	var app struct {
		ClientName string    `json:"client_name"`
		TenantID   uuid.UUID `json:"tenant_id"`
	}
	dbtest.Decode(t, browse(t, p.public, http.MethodGet, "/oauth/login-context?client_id="+client.ClientID, nil, nil), &app)
	if app.ClientName != client.Name || app.TenantID != tenant {
		t.Errorf("login context %+v, want the application's name and organisation", app)
	}
	if rec := browse(t, p.public, http.MethodGet, "/oauth/login-context?client_id=qci_unknown", nil, nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCClientNotFound) {
		t.Errorf("login context for an unknown client: %d %s", rec.Code, rec.Body.String())
	}
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, nil, nil))
	if to != loginBase+"/login" || q.Get("return_to") != publicBase+target {
		t.Errorf("signed out: sent to %s to return to %q, want the hosted login and back to the request", to, q.Get("return_to"))
	}
	to, q = redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	requestID := q.Get("request_id")
	if to != loginBase+"/consent" || requestID == "" || len(q) != 1 {
		t.Fatalf("signed in without consent: sent to %s %v, want the consent screen with only a request id", to, q)
	}

	consent := "/oauth/authorize/request?request_id=" + requestID
	if rec := browse(t, p.public, http.MethodGet, consent, otherBrowser, nil); !strings.Contains(rec.Body.String(), errs.CodeOIDCConsentRequestInvalid) {
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
	if rec := browse(t, p.public, http.MethodPost, decide, otherBrowser, approve); !strings.Contains(rec.Body.String(), errs.CodeOIDCConsentRequestInvalid) {
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
	if rec := browse(t, p.public, http.MethodPost, decide, cookie, approve); !strings.Contains(rec.Body.String(), errs.CodeOIDCConsentRequestInvalid) {
		t.Errorf("decide the request twice: %d %s", rec.Code, rec.Body.String())
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}}
	rec = postForm(t, p.public, "/oauth/token-code", form, client.ClientID, secret)
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
		"sid": sessionID.String(), "tenant_id": tenant.String(), "email": person.Email, "email_verified": false,
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
	noOpenID := dbtest.Principal(person.ID, tenant)
	noOpenID.Scopes = []string{"email"}
	rec = dbtest.Do(t, dbtest.Serve(noOpenID, p.mount), http.MethodPost, "/oauth/userinfo", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Errorf("userinfo without openid: %d %q, want 403 insufficient_scope", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

// TestAuthorizeRemembersConsentAndHonoursPrompt checks that consent once given
// lets a later request straight back with a code, that prompt=consent asks
// again and an echoed value that differs from the stored request spends it,
// and that prompt=none and prompt=login are answered without a screen.
func TestAuthorizeRemembersConsentAndHonoursPrompt(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, _ := registerClient(t, p.svc, tenant)
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
	if to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil)); to != loginBase+"/login" || q.Get("prompt") != "login" ||
		!strings.Contains(q.Get("return_to"), loginAfterParam+"=") {
		t.Errorf("prompt=login: sent to %s %v, want a fresh hosted sign-in that comes back", to, q)
	}

	target, _ = authorizeURL(t, client.ClientID, "scope", "openid email", "prompt", "consent")
	to, q = redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != loginBase+"/consent" {
		t.Fatalf("prompt=consent: sent to %s, want the consent screen", to)
	}
	tampered := map[string]any{"request_id": q.Get("request_id"), "approve": true, "redirect_uri": "https://evil.example.test/callback"}
	for _, body := range []map[string]any{tampered, {"request_id": q.Get("request_id"), "approve": true}} {
		if rec := browse(t, p.public, http.MethodPost, "/oauth/authorize/decision", cookie, body); !strings.Contains(rec.Body.String(), errs.CodeOIDCConsentRequestInvalid) {
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
	tenant, otherTenant := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	outsider := dbtest.User(t, otherTenant, otherTenant)
	client, _ := registerClient(t, p.svc, tenant)
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
		if rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), errs.CodeOIDCRedirectURINotRegistered) {
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
		{"openid without a nonce", []string{"nonce", ""}, cookie, "invalid_request"},
		{"an unregistered resource", []string{"resource", "https://api.example.test"}, cookie, "invalid_target"},
		{"a person of another organisation", nil, outsiderCookie, "access_denied"},
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

// TestAuthorizeRefusesScopesBeforeConsent checks that a request for a scope
// the application may not have goes back to it as invalid_scope, before the
// person is asked to consent to it.
func TestAuthorizeRefusesScopesBeforeConsent(t *testing.T) {
	p := newProvider(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, _ := registerClient(t, p.svc, tenant)
	cookie, _ := p.signIn(t, person.ID)

	target, _ := authorizeURL(t, client.ClientID, "scope", "openid admin")
	to, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	if to != testRedirect || q.Get("error") != "invalid_scope" {
		t.Errorf("a scope the application may not have: sent to %s %v, want invalid_scope", to, q)
	}
}

// TestDiscoveryNamesTheIssuerTokensCarry checks that both metadata documents
// name as issuer the iss of the authorization response and of the ID token,
// which relying parties compare exactly.
func TestDiscoveryNamesTheIssuerTokensCarry(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, p.svc, tenant)
	cookie, _ := p.signIn(t, person.ID)
	if err := p.svc.GrantConsent(ctx, person.ID, client.ClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent: %v", err)
	}
	target, verifier := authorizeURL(t, client.ClientID)
	_, q := redirected(t, browse(t, p.public, http.MethodGet, target, cookie, nil))
	issued, err := p.svc.ExchangeCode(ctx, client.ClientID, secret, q.Get("code"), testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem the code: %v", err)
	}
	id, err := p.svc.issuer.VerifySigned(issued.IDToken)
	if err != nil {
		t.Fatalf("verify the ID token: %v", err)
	}

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		var doc map[string]any
		dbtest.Decode(t, browse(t, p.public, http.MethodGet, path, nil, nil), &doc)
		if doc["issuer"] != q.Get("iss") || doc["issuer"] != id["iss"] {
			t.Errorf("%s issuer %v; the authorization response says %q and the ID token %v", path, doc["issuer"], q.Get("iss"), id["iss"])
		}
	}
}

// TestCodeRedemptionRules checks that a code redeems only for the application
// it was issued to, at its redirect_uri, before it expires and while the
// account is active, and that a PKCE exemption waives the proof key only for
// a confidential application and only while it lasts.
func TestCodeRedemptionRules(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := NewService(pool, dbtest.Issuer(t))
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	client, secret := registerClient(t, svc, tenant)
	sibling, siblingSecret := registerClient(t, svc, tenant)
	public, _ := registerClientWith(t, svc, CreateClientInput{TenantID: tenant, Type: "public"})
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
	if _, err := svc.ExchangeCode(ctx, sibling.ClientID, siblingSecret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeInvalid) {
		t.Errorf("redeem by another application: %v, want %v", err, errs.ErrOIDCAuthCodeInvalid)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect+"/other", verifier, ""); !errors.Is(err, errs.ErrOIDCRedirectURIMismatch) {
		t.Errorf("redeem at another redirect_uri: %v, want %v", err, errs.ErrOIDCRedirectURIMismatch)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); err != nil {
		t.Errorf("redeem after the refused attempts: %v", err)
	}

	code, verifier = authorize(client.ClientID)
	if _, err := pool.Exec(ctx, `UPDATE auth.oidc_authorization_codes SET expires_at = NOW() - INTERVAL '1 second'
		WHERE tenant_id = $1 AND code_hash = $2`, tenant, codes.Hash(code)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeExpired) {
		t.Errorf("redeem an expired code: %v, want %v", err, errs.ErrOIDCAuthCodeExpired)
	}

	code, verifier = authorize(client.ClientID)
	setStatus := func(status string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = $2 WHERE tenant_id = $1 AND id = $3`, tenant, status, person.ID); err != nil {
			t.Fatal(err)
		}
	}
	setStatus("suspended")
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrAuthAccountSuspended) {
		t.Errorf("redeem for a suspended account: %v, want %v", err, errs.ErrAuthAccountSuspended)
	}
	setStatus("active")
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeUsed) {
		t.Errorf("redeem again once the account is back: %v, want %v (the code is spent)", err, errs.ErrOIDCAuthCodeUsed)
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
		if _, err := svc.UpdateClient(ctx, tx, tenant, c.ID, UpdateClientInput{PKCEExemptUntil: OptionalTime{Set: true, At: until}}); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	soon, tooLate := time.Now().Add(time.Hour), time.Now().Add(pkceExemptionMax+time.Hour)
	if err := exemption(public, &soon); !errors.Is(err, errs.ErrOIDCPKCEExemptionInvalid) {
		t.Errorf("exempt a public application: %v, want %v", err, errs.ErrOIDCPKCEExemptionInvalid)
	}
	if err := exemption(client, &tooLate); !errors.Is(err, errs.ErrOIDCPKCEExemptionInvalid) {
		t.Errorf("exempt for longer than allowed: %v, want %v", err, errs.ErrOIDCPKCEExemptionInvalid)
	}
	if _, _, err := svc.Authorize(ctx, person.ID, public.ClientID, testRedirect, []string{"openid"}, "n-1", "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
		t.Errorf("a public application without a challenge: %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
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
	if _, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, "", ""); !errors.Is(err, errs.ErrOIDCCodeChallengeRequired) {
		t.Errorf("redeem an unproved code after the exemption ended: %v, want %v", err, errs.ErrOIDCCodeChallengeRequired)
	}
}
