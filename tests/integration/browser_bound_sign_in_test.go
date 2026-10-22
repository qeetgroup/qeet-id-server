//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// socialCallback is the provider's return to the social callback as it arrives
// in the browser that began the sign-in with this state, carrying the binding
// start gave it (the handlers here aren't Secure, so it has no __Host- prefix).
func socialCallback(provider, state string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/callback?"+
		url.Values{"state": {state}, "code": {"upstream-code"}}.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: "qe_social", Value: state})
	return r
}

// browser keeps one browser's cookies across requests.
type browser struct{ jar map[string]*http.Cookie }

func newBrowser() *browser { return &browser{jar: map[string]*http.Cookie{}} }

func (b *browser) do(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	for _, c := range b.jar {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c
		}
	}
	return rr
}

// setsCookie reports whether a response gave the browser the named cookie.
func setsCookie(rr *httptest.ResponseRecorder, name string) bool {
	for _, c := range rr.Result().Cookies() {
		if c.Name == name && c.Value != "" && c.MaxAge >= 0 {
			return true
		}
	}
	return false
}

// TestASocialSignInCompletesOnlyInTheBrowserThatBeganIt: a social sign-in
// remembered its request by the state alone, so someone who began one with
// their own provider account and stopped before the return could send the
// return link on, and whoever opened it was signed in as the sender — in an
// organisation's hosted and application flows and in the console's own. The
// browser that begins a sign-in is now given a binding the return must carry:
// opened in another browser, or without it, the return is refused and nothing
// is issued; in the browser that began it, it completes as before.
func TestASocialSignInCompletesOnlyInTheBrowserThatBeganIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("bound"))
	setSelfRegistration(t, ctx, tenantID, true)
	sub := uniqueSlug("sender")
	idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true,"name":"Sender"}`, sub, sub+"@example.com"))
	t.Cleanup(idp.Close)
	discovery := idp.URL + "/.well-known/openid-configuration"
	orgProvider, consoleProvider := uniqueSlug("org-idp"), uniqueSlug("console-idp")
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
		VALUES ($1, $2, 'cid', 'csecret', $3)`, tenantID, orgProvider, discovery); err != nil {
		t.Fatal(err)
	}
	svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
	svc.SetCipher(testEnvelope(t))
	svc.SetAllowedReturnOrigins("https://app.example")
	svc.SetPlatformProvider(consoleProvider, "cid", "csecret", discovery)
	router := chi.NewRouter()
	router.Route("/v1", (&social.Handler{Service: svc, LoginBaseURL: "http://login.test", CookieSecure: true}).MountPublic)
	const returnTo = "https://app.example/oauth/authorize?client_id=rp"

	start := func(t *testing.T, b *browser, provider, query string) string {
		t.Helper()
		rr := b.do(router, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/start?"+query, nil))
		loc, _ := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || loc == nil || loc.Query().Get("state") == "" {
			t.Fatalf("start = %d %s, want a redirect to the provider", rr.Code, rr.Header().Get("Location"))
		}
		return loc.Query().Get("state")
	}
	returnIn := func(b *browser, provider, state string) *httptest.ResponseRecorder {
		return b.do(router, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/callback?"+
			url.Values{"state": {state}, "code": {"upstream-code"}}.Encode(), nil))
	}
	codesMinted := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `
			SELECT (SELECT count(*) FROM auth.social_login_codes WHERE tenant_id = $1)
			     + (SELECT count(*) FROM auth.platform_social_codes)`, tenantID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("the binding is script-inaccessible and carried by a cross-site form_post", func(t *testing.T) {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/social/"+orgProvider+"/start?tenant_id="+tenantID.String(), nil))
		var binding *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == "__Host-qe_social" {
				binding = c
			}
		}
		if binding == nil || !binding.HttpOnly || !binding.Secure || binding.SameSite != http.SameSiteNoneMode || binding.Path != "/" || binding.Domain != "" {
			t.Fatalf("binding cookie = %+v, want __Host-qe_social, HttpOnly, Secure, SameSite=None, on / with no domain", binding)
		}
	})

	for _, flow := range []struct {
		name, provider, query string
		refused               func(*url.URL) bool
		completed             func(*httptest.ResponseRecorder) bool
	}{
		{
			name: "an organisation's hosted sign-in", provider: orgProvider,
			query: url.Values{"tenant_id": {tenantID.String()}, "return_to": {returnTo}}.Encode(),
			refused: func(u *url.URL) bool {
				return u.Host == "login.test" && u.Path == "/login" && u.Query().Get("error") == "other_browser" && u.Query().Get("return_to") == returnTo
			},
			completed: func(rr *httptest.ResponseRecorder) bool {
				return rr.Header().Get("Location") == returnTo && setsCookie(rr, auth.LoginSessionCookie)
			},
		},
		{
			name: "an organisation's application sign-in", provider: orgProvider,
			query: url.Values{"tenant_id": {tenantID.String()}}.Encode(),
			refused: func(u *url.URL) bool {
				return u.Host == "login.test" && u.Path == "/login" && u.Query().Get("error") == "other_browser"
			},
			completed: func(rr *httptest.ResponseRecorder) bool {
				u, _ := url.Parse(rr.Header().Get("Location"))
				return u != nil && u.Host == "app.local" && u.Path == "/auth/social/callback" && u.Query().Get("code") != ""
			},
		},
		{
			name: "the console's own sign-in", provider: consoleProvider, query: "intent=signup",
			refused: func(u *url.URL) bool {
				return u.Host == "app.local" && u.Path == "/sign-in" && u.Query().Get("social_error") == "other_browser"
			},
			completed: func(rr *httptest.ResponseRecorder) bool {
				u, _ := url.Parse(rr.Header().Get("Location"))
				return u != nil && u.Host == "app.local" && u.Path == "/sign-in" && u.Query().Get("social_code") != ""
			},
		},
	} {
		t.Run(flow.name, func(t *testing.T) {
			sender := newBrowser()
			refusedIn := func(t *testing.T, b *browser) {
				t.Helper()
				before := codesMinted(t)
				rr := returnIn(b, flow.provider, start(t, sender, flow.provider, flow.query))
				loc, _ := url.Parse(rr.Header().Get("Location"))
				if rr.Code != http.StatusFound || loc == nil || !flow.refused(loc) {
					t.Fatalf("the return link opened elsewhere = %d %s, want it refused with other_browser", rr.Code, rr.Header().Get("Location"))
				}
				if setsCookie(rr, auth.LoginSessionCookie) || loc.Query().Get("code") != "" || loc.Query().Get("social_code") != "" || codesMinted(t) != before {
					t.Fatalf("a refused return issued something: %s", rr.Header().Get("Location"))
				}
			}

			// The sender's return link, opened by someone else.
			refusedIn(t, newBrowser())
			// ... and by someone with a sign-in of their own under way.
			other := newBrowser()
			start(t, other, flow.provider, flow.query)
			refusedIn(t, other)

			// In the browser that began it, it completes as before.
			if rr := returnIn(sender, flow.provider, start(t, sender, flow.provider, flow.query)); rr.Code != http.StatusFound || !flow.completed(rr) {
				t.Fatalf("the return in the browser that began it = %d %s", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}

// TestConnectingAProviderCompletesOnlyForTheAccountThatBeganIt: connecting a
// provider attached whatever the provider returned to the account the link was
// asked for, in whichever browser the return arrived. So a connect link sent to
// someone else attached their provider account to the sender's, and whoever
// signed in with it later landed in the sender's account. The return now
// attaches nothing: the account page completes the link, and only for the
// account that began it.
func TestConnectingAProviderCompletesOnlyForTheAccountThatBeganIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	subject := uniqueSlug("their-sub")
	idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true}`, subject, subject+"@example.com"))
	t.Cleanup(idp.Close)
	provider := uniqueSlug("link-idp")
	authSvc, _ := newAuth()
	svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
	svc.SetPlatformProvider(provider, "cid", "csecret", idp.URL+"/.well-known/openid-configuration")
	h := &social.Handler{Service: svc, LoginBaseURL: "http://login.test", CookieSecure: true}
	public := chi.NewRouter()
	public.Route("/v1", h.MountPublic)
	account := func(userID uuid.UUID) http.Handler {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Use(withPrincipal(userID, uuid.Nil))
			h.Mount(r)
		})
		return r
	}
	person := func() uuid.UUID {
		var id uuid.UUID
		if err := testPool.QueryRow(ctx, `INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, uniqueSlug("person")+"@example.com").Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	linkedTo := func(t *testing.T) []uuid.UUID {
		t.Helper()
		rows, err := testPool.Query(ctx, `SELECT user_id FROM auth.platform_social_identities WHERE provider = $1 AND subject = $2`, provider, subject)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		return ids
	}
	// returnFor begins a link for userID (through the console's server, so no
	// browser binding) and returns the link code the return hands the account
	// page, checking nothing was attached yet.
	returnFor := func(t *testing.T, userID uuid.UUID) string {
		t.Helper()
		authURL, err := svc.BeginPlatformLink(ctx, provider, "http://api.local/v1/social/"+provider+"/callback", userID)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(authURL)
		rr := newBrowser().do(public, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/callback?"+
			url.Values{"state": {u.Query().Get("state")}, "code": {"upstream-code"}}.Encode(), nil))
		loc, _ := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || loc == nil || loc.Host != "app.local" || loc.Path != "/account/security" ||
			loc.Query().Get("provider") != provider || loc.Query().Get("link_code") == "" {
			t.Fatalf("link return = %d %s, want the account page with a link code", rr.Code, rr.Header().Get("Location"))
		}
		if ids := linkedTo(t); len(ids) != 0 {
			t.Fatalf("the return attached the identity to %v before any account completed it", ids)
		}
		return loc.Query().Get("link_code")
	}
	complete := func(userID uuid.UUID, code string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/v1/social/link/complete", strings.NewReader(fmt.Sprintf(`{"code":%q}`, code)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		account(userID).ServeHTTP(rr, req)
		return rr.Code, errorCode(t, rr)
	}
	sender, recipient := person(), person()

	code := returnFor(t, sender)
	if status, errCode := complete(recipient, code); status != http.StatusForbidden || errCode != errs.CodeSocialLinkAccountMismatch {
		t.Fatalf("completed by the account the link was sent to = %d %s, want 403 social.link_account_mismatch", status, errCode)
	}
	if ids := linkedTo(t); len(ids) != 0 {
		t.Fatalf("a refused completion attached the identity to %v", ids)
	}
	if status, errCode := complete(sender, code); status != http.StatusBadRequest || errCode != errs.CodeSocialLinkCodeInvalid {
		t.Fatalf("a code spent by the wrong account, completed again = %d %s, want 400 social.link_code_invalid", status, errCode)
	}

	code = returnFor(t, sender)
	if status, errCode := complete(sender, code); status != http.StatusOK {
		t.Fatalf("completed by the account that began it = %d %s, want 200", status, errCode)
	}
	if ids := linkedTo(t); len(ids) != 1 || ids[0] != sender {
		t.Fatalf("identity linked to %v, want only the account that began the link", ids)
	}
}

// TestAPasskeySignInSignsInOnlyTheBrowserThatBeganIt: passkey sign-in finish
// set the hosted-login cookie, yet skipped the cross-site check (it is there to
// hand out a bearer token), decoded its body whatever it was sent as, and
// nothing tied the ceremony to a browser. So a page on another site could post
// its owner's own signed assertion, as a text/plain form, from a visitor's
// browser, which was then signed in to the hosted login as that owner. The
// hosted form (login/session) now takes only JSON, keeps the cross-site check,
// and finishes only in the browser that began the ceremony, leaving it
// untouched for any other; the token form (login/finish) sets no cookie.
func TestAPasskeySignInSignsInOnlyTheBrowserThatBeganIt(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newPasskeySvc(t)
	pk := newPasskeyAccount(t, ctx, svc)
	router := chi.NewRouter()
	router.Route("/v1", (&passkey.Handler{Service: svc}).MountPublic)
	owner, visitor := newBrowser(), newBrowser()

	signed := pk.begin(t, router, owner)
	rr := pk.post(router, visitor, "/v1/passkeys/login/session", "text/plain", signed)
	if rr.Code != http.StatusUnsupportedMediaType || errorCode(t, rr) != errs.CodeUnsupportedMedia || setsCookie(rr, auth.LoginSessionCookie) {
		t.Fatalf("the owner's assertion posted cross-site as text/plain = %d %s, cookie %v; want 415 and no cookie",
			rr.Code, rr.Body.String(), setsCookie(rr, auth.LoginSessionCookie))
	}
	rr = pk.post(router, visitor, "/v1/passkeys/login/session", "application/json", signed)
	if rr.Code != http.StatusForbidden || errorCode(t, rr) != errs.CodePasskeyBrowserMismatch || setsCookie(rr, auth.LoginSessionCookie) {
		t.Fatalf("the owner's assertion finished in another browser = %d %s; want 403 passkey.browser_mismatch and no cookie", rr.Code, rr.Body.String())
	}
	// A browser with a ceremony of its own under way isn't signed in by
	// someone else's either.
	pk.begin(t, router, visitor)
	if rr := pk.post(router, visitor, "/v1/passkeys/login/session", "application/json", signed); rr.Code != http.StatusForbidden || setsCookie(rr, auth.LoginSessionCookie) {
		t.Fatalf("another ceremony finished in a browser with its own = %d; want 403 and no cookie", rr.Code)
	}
	// The token form sets no cookie for anyone.
	if rr := pk.post(router, visitor, "/v1/passkeys/login/finish", "application/json", pk.begin(t, router, owner)); rr.Code != http.StatusOK || setsCookie(rr, auth.LoginSessionCookie) {
		t.Fatalf("the token form = %d, cookie %v; want the token pair and no cookie", rr.Code, setsCookie(rr, auth.LoginSessionCookie))
	}

	// The refusals left the ceremony untouched: the browser that began it
	// finishes it and is signed in.
	if rr := pk.post(router, owner, "/v1/passkeys/login/session", "application/json", signed); rr.Code != http.StatusOK || !setsCookie(rr, auth.LoginSessionCookie) {
		t.Fatalf("finished in the browser that began it = %d %s, cookie %v; want the hosted-login cookie", rr.Code, rr.Body.String(), setsCookie(rr, auth.LoginSessionCookie))
	}
}

// passkeyAccount is a passkey-only account on a virtual authenticator.
type passkeyAccount struct {
	rp virtualwebauthn.RelyingParty
	a  virtualwebauthn.Authenticator
	c  virtualwebauthn.Credential
}

func newPasskeyAccount(t *testing.T, ctx context.Context, svc *passkey.Service) *passkeyAccount {
	t.Helper()
	pk := &passkeyAccount{
		rp: virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin},
		a:  virtualwebauthn.NewAuthenticator(),
		c:  virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	sid, creation, err := svc.BeginSignup(ctx, uniqueSlug("owner")+"@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	creationJSON, _ := json.Marshal(creation)
	opts, err := virtualwebauthn.ParseAttestationOptions(string(creationJSON))
	if err != nil {
		t.Fatal(err)
	}
	pk.a.Options.UserHandle = []byte(opts.UserID)
	if _, _, err := svc.FinishSignup(ctx, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(pk.rp, pk.a, pk.c, *opts)), "", "203.0.113.7", "test"); err != nil {
		t.Fatalf("passkey sign-up: %v", err)
	}
	pk.a.AddCredential(pk.c)
	return pk
}

func (pk *passkeyAccount) post(router http.Handler, b *browser, path, contentType string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	return b.do(router, req)
}

// begin starts a ceremony in b and returns the account's signed finish body.
func (pk *passkeyAccount) begin(t *testing.T, router http.Handler, b *browser) []byte {
	t.Helper()
	rr := pk.post(router, b, "/v1/passkeys/login/begin", "application/json", []byte(`{}`))
	var out struct {
		SessionID uuid.UUID       `json:"session_id"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &out) != nil {
		t.Fatalf("begin = %d %s", rr.Code, rr.Body.String())
	}
	options, _ := json.Marshal(map[string]json.RawMessage{"publicKey": out.PublicKey})
	aopts, err := virtualwebauthn.ParseAssertionOptions(string(options))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"session_id": out.SessionID,
		"credential": json.RawMessage(virtualwebauthn.CreateAssertionResponse(pk.rp, pk.a, pk.c, *aopts)),
	})
	return body
}

// TestRoutesThatSignABrowserInTakeOnlyJSON: request bodies were decoded as
// JSON whatever content type they arrived with, so a page on another site
// could make a browser post one to a route that sets the hosted-login cookie
// as a text/plain form, without the browser asking first. Those routes now
// refuse a body not sent as JSON, before looking at it.
func TestRoutesThatSignABrowserInTakeOnlyJSON(t *testing.T) {
	requireDB(t)
	authSvc, _ := newAuth()
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).Mount(r)
		(&passkey.Handler{Service: newPasskeySvcWithAuth(t, authSvc)}).MountPublic(r)
		(&recovery.Handler{Service: newRecovery(&mailbox{}), AuthService: authSvc}).Mount(r)
	})
	for path, body := range map[string]string{
		"/v1/auth/session":            `{"email":"someone@example.com","password":"Kx7mQ2vLp9Wz"}`,
		"/v1/auth/session/mfa":        `{"mfa_token":"token","code":"123456"}`,
		"/v1/auth/register":           `{"tenant_id":"` + uuid.NewString() + `","email":"someone@example.com","password":"Kx7mQ2vLp9Wz"}`,
		"/v1/auth/magic-link/session": `{"token":"token"}`,
		"/v1/passkeys/login/begin":    `{}`,
		"/v1/passkeys/login/finish":   `{"session_id":"` + uuid.NewString() + `","credential":{}}`,
		"/v1/register/passkey/finish": `{"session_id":"` + uuid.NewString() + `","credential":{}}`,
	} {
		for _, contentType := range []string{"text/plain", "application/x-www-form-urlencoded", ""} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnsupportedMediaType || errorCode(t, rr) != errs.CodeUnsupportedMedia || len(rr.Result().Cookies()) != 0 {
				t.Errorf("POST %s as %q = %d %s, cookies %d; want 415 unsupported_media_type and no cookie",
					path, contentType, rr.Code, rr.Body.String(), len(rr.Result().Cookies()))
			}
		}
	}
}
