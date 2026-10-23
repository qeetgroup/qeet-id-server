//go:build integration

package social

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// identityProvider is a fake OIDC provider. Each authorization code it will
// accept is registered with expect, with the PKCE challenge it was issued for
// and the person it signs in.
type identityProvider struct {
	*httptest.Server
	mu    sync.Mutex
	codes map[string]pendingCode
}

// pendingCode is an authorization code the provider will accept.
type pendingCode struct {
	challenge string
	person    userInfo
}

// newIdentityProvider starts the provider until t ends.
func newIdentityProvider(t *testing.T) *identityProvider {
	p := &identityProvider{codes: map[string]pendingCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryDoc{
			AuthorizationEndpoint: "https://idp.example.test/authorize",
			TokenEndpoint:         p.URL + "/token",
			UserinfoEndpoint:      p.URL + "/userinfo",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		pending, ok := p.codes[r.PostForm.Get("code")]
		p.mu.Unlock()
		if !ok || r.PostForm.Get("client_secret") != "idp-client-secret" || codes.Hash(r.PostForm.Get("code_verifier")) != pending.challenge {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at-" + r.PostForm.Get("code")})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		pending, ok := p.codes[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")]
		p.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(pending.person)
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// expect makes the provider accept code for the sign-in authURL began, as
// person.
func (p *identityProvider) expect(t *testing.T, authURL, code string, person userInfo) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, "https://idp.example.test/authorize?") || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL %q; want the provider's, with PKCE", authURL)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.codes[code] = pendingCode{challenge: u.Query().Get("code_challenge"), person: person}
}

// browse sends a request as a browser holding cookies.
func browse(t *testing.T, h http.Handler, method, target string, cookies []*http.Cookie, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequestWithContext(dbtest.Context(t), method, target, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// socialFixture is a social sign-in service with a fake provider, its public
// and authenticated routes.
type socialFixture struct {
	svc    *Service
	idp    *identityProvider
	public http.Handler
	mount  func(chi.Router)
}

// newSocialFixture returns the fixture, allowing return to app.example.test.
func newSocialFixture(t *testing.T) *socialFixture {
	t.Helper()
	pool := dbtest.Pool(t)
	authSvc := auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t))
	authSvc.SetRegistrationPolicy(authpolicy.NewService(pool))
	svc := NewService(pool, authSvc, "https://console.example.test", egress.DevelopmentPolicy())
	box, err := envelope.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc.SetCipher(box)
	svc.SetAllowedReturnOrigins("https://app.example.test")
	h := &Handler{Service: svc, LoginBaseURL: "https://login.example.test", PublicBaseURL: "https://id.example.test"}
	public := chi.NewRouter()
	h.MountPublic(public)
	return &socialFixture{svc: svc, idp: newIdentityProvider(t), public: public, mount: h.Mount}
}

// signIn runs a browser through a sign-in begun at start, the provider
// answering as person, and returns the callback's response.
func (f *socialFixture) signIn(t *testing.T, provider, start string, person userInfo) *httptest.ResponseRecorder {
	t.Helper()
	begun := browse(t, f.public, http.MethodGet, start, nil, nil)
	if begun.Code != http.StatusFound {
		t.Fatalf("start %s: %d %s", start, begun.Code, begun.Header().Get("Location"))
	}
	authURL := begun.Header().Get("Location")
	code := uuid.NewString()
	f.idp.expect(t, authURL, code, person)
	return browse(t, f.public, http.MethodGet, "/social/"+provider+"/callback?state="+url.QueryEscape(stateOf(authURL))+"&code="+code, begun.Result().Cookies(), nil)
}

// redirectQuery returns a redirect's target and query.
func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil {
		t.Fatalf("want a redirect, got %d %s", rec.Code, rec.Body.String())
	}
	return u.Scheme + "://" + u.Host + u.Path, u.Query()
}

// verified marks a's address verified and returns the provider's claims for a.
func verified(t *testing.T, a dbtest.Account) userInfo {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `UPDATE "user".users SET email_verified_at = NOW() WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	return userInfo{Subject: "sub-" + a.ID.String(), Email: a.Email, EmailVerified: true, Name: "Asha"}
}

// TestOrganisationSocialSignIn checks an organisation's own provider end to
// end: it is configured without its secret ever being returned; a sign-in
// completes only in the browser that began it, with PKCE, for a one-time code
// that buys a session once; the hosted flow returns to an allowed application
// signed in; and a closed organisation, a suspended account, a switched-off
// provider and a provider people depend on are each refused.
func TestOrganisationSocialSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSocialFixture(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), f.mount)

	rec := dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", map[string]string{
		"provider": "okta", "client_id": "qeet", "client_secret": "idp-client-secret",
		"discovery_url": f.idp.URL + "/.well-known/openid-configuration",
	})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "idp-client-secret") {
		t.Fatalf("add provider: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", map[string]string{"provider": "okta", "client_id": "qeet-2", "discovery_url": f.idp.URL + "/.well-known/openid-configuration"}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"qeet-2"`) {
		t.Errorf("replace keeping the secret: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/social/providers", nil); !strings.Contains(rec.Body.String(), `"okta"`) || strings.Contains(rec.Body.String(), "idp-client-secret") {
		t.Errorf("providers: %s", rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", map[string]string{"provider": "evil", "client_id": "x", "client_secret": "y", "discovery_url": "ftp://idp.example.test"}); rec.Code/100 != 4 {
		t.Errorf("a provider without an http discovery URL: %d, want refused", rec.Code)
	}

	member := dbtest.User(t, tenant, tenant)
	person := verified(t, member)
	start := "/social/okta/start?tenant_id=" + tenant.String()
	target, q := redirectQuery(t, f.signIn(t, "okta", start, person))
	if target != "https://console.example.test/auth/social/callback" || q.Get("code") == "" {
		t.Fatalf("callback went to %s %v; want the console with a one-time code", target, q)
	}
	rec = browse(t, f.public, http.MethodPost, "/social/exchange", nil, map[string]string{"code": q.Get("code")})
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	if rec := browse(t, f.public, http.MethodPost, "/social/exchange", nil, map[string]string{"code": q.Get("code")}); rec.Code == http.StatusOK {
		t.Error("a one-time code bought a second session")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".external_identities WHERE user_id = $1 AND tenant_id = $2 AND provider = 'okta'`, member.ID, tenant); n != 1 {
		t.Errorf("%d identities linked, want 1", n)
	}

	begun := browse(t, f.public, http.MethodGet, start, nil, nil)
	authURL := begun.Header().Get("Location")
	f.idp.expect(t, authURL, "elsewhere", person)
	callback := "/social/okta/callback?state=" + url.QueryEscape(stateOf(authURL)) + "&code=elsewhere"
	if _, q := redirectQuery(t, browse(t, f.public, http.MethodGet, callback, nil, nil)); q.Get("error") != "other_browser" {
		t.Errorf("a callback in another browser: %v, want other_browser", q)
	}
	if _, q := redirectQuery(t, browse(t, f.public, http.MethodGet, callback, begun.Result().Cookies(), nil)); q.Get("error") != "social" {
		t.Errorf("the same state used again: %v, want refused", q)
	}

	returnTo := "https://app.example.test/oauth/authorize?client_id=app"
	rec = f.signIn(t, "okta", start+"&return_to="+url.QueryEscape(returnTo), person)
	signedIn := false
	for _, c := range rec.Result().Cookies() {
		signedIn = signedIn || (c.Name == auth.LoginSessionCookie && c.Value != "")
	}
	if rec.Header().Get("Location") != returnTo || !signedIn {
		t.Errorf("hosted sign-in went to %q, signed in %v; want the application, signed in", rec.Header().Get("Location"), signedIn)
	}
	if rec := browse(t, f.public, http.MethodGet, start+"&return_to="+url.QueryEscape("https://evil.example.test/"), nil, nil); !strings.HasPrefix(rec.Header().Get("Location"), "https://login.example.test/login?error=social") {
		t.Errorf("a return_to on another origin: %d %s, want refused", rec.Code, rec.Header().Get("Location"))
	}

	if _, q := redirectQuery(t, f.signIn(t, "okta", start, userInfo{Subject: "newcomer", Email: dbtest.Unique("new") + "@example.test", EmailVerified: true})); q.Get("error") != "registration_closed" {
		t.Errorf("a newcomer to a closed organisation: %v, want registration_closed", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'social.signup_refused'`, tenant); n != 1 {
		t.Errorf("%d refused sign-ups recorded, want 1", n)
	}
	suspended := dbtest.User(t, tenant, tenant)
	suspendedPerson := verified(t, suspended)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, q := redirectQuery(t, f.signIn(t, "okta", start, suspendedPerson)); q.Get("error") != "account_inactive" {
		t.Errorf("a suspended account: %v, want account_inactive", q)
	}

	var identities struct {
		Items []ExternalIdentity `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/users/"+member.ID.String()+"/social/identities", nil), &identities)
	if len(identities.Items) != 1 {
		t.Fatalf("member's identities %+v, want 1", identities.Items)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/providers/okta", nil); !strings.Contains(rec.Body.String(), errs.CodeSocialProviderInUse) {
		t.Errorf("delete a provider people sign in with only: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/identities/"+identities.Items[0].ID.String(), nil); !strings.Contains(rec.Body.String(), errs.CodeAuthLastSignInMethod) {
		t.Errorf("unlink a member's only way to sign in: %d %s", rec.Code, rec.Body.String())
	}
	dbtest.SetPassword(t, member.ID, "Kx7mQ2vLp9Wz")
	dbtest.SetPassword(t, suspended.ID, "Kx7mQ2vLp9Wz")
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/identities/"+identities.Items[0].ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("unlink beside a password: %d %s", rec.Code, rec.Body.String())
	}

	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, "/social/providers/okta", map[string]bool{"enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("switch off: %d %s", rec.Code, rec.Body.String())
	}
	if rec := browse(t, f.public, http.MethodGet, start, nil, nil); !strings.HasPrefix(rec.Header().Get("Location"), "https://login.example.test/login?error=social") {
		t.Errorf("start with a switched-off provider: %s", rec.Header().Get("Location"))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action LIKE 'social_provider.%'`, tenant); n != 3 {
		t.Errorf("%d provider changes recorded, want created, updated and disabled", n)
	}
	other := dbtest.Tenant(t)
	otherAdmin := dbtest.User(t, other, other)
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), f.mount), http.MethodPatch, "/social/providers/okta", map[string]bool{"enabled": true}); rec.Code != http.StatusNotFound {
		t.Errorf("another organisation switching the provider on: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/providers/okta", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete provider: %d %s", rec.Code, rec.Body.String())
	}
}

// TestPlatformSocialSignIn checks the console's own sign-in: sign-up creates
// an account only when asked to, sign-in needs one, and a signed-in person can
// link the provider to their account, which only they can complete and unlink.
func TestPlatformSocialSignIn(t *testing.T) {
	f := newSocialFixture(t)
	f.svc.SetPlatformProvider("google", "qeet", "idp-client-secret", f.idp.URL+"/.well-known/openid-configuration")
	if names := f.svc.PlatformProviderNames(); len(names) != 1 || names[0] != "google" {
		t.Errorf("platform providers %v", names)
	}
	newcomer := userInfo{Subject: "g-" + uuid.NewString(), Email: dbtest.Unique("g") + "@example.test", EmailVerified: true, Name: "Ravi"}

	if target, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start", newcomer)); target != "https://console.example.test/sign-in" || q.Get("social_error") != "no_account" {
		t.Errorf("sign in without an account: %s %v, want no_account", target, q)
	}
	target, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start?intent=signup", newcomer))
	if target != "https://console.example.test/sign-in" || q.Get("social_code") == "" {
		t.Fatalf("sign up: %s %v", target, q)
	}
	rec := browse(t, f.public, http.MethodPost, "/social/exchange", nil, map[string]string{"code": q.Get("social_code")})
	var pair auth.TokenPair
	dbtest.Decode(t, rec, &pair)
	if rec.Code != http.StatusOK || pair.AccessToken == "" {
		t.Fatalf("exchange: %d %s", rec.Code, rec.Body.String())
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM "user".users WHERE email = $1`, newcomer.Email); n != 1 {
		t.Errorf("%d accounts for the newcomer, want 1", n)
	}
	if _, q := redirectQuery(t, f.signIn(t, "google", "/social/google/start", newcomer)); q.Get("social_code") == "" {
		t.Errorf("sign in again: %v", q)
	}

	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	asA := dbtest.Serve(dbtest.Principal(a.ID, tenant), f.mount)
	link := func(code string) string {
		t.Helper()
		rec := dbtest.Do(t, asA, http.MethodPost, "/social/google/link/start", nil)
		var started struct {
			AuthorizeURL string `json:"authorize_url"`
		}
		dbtest.Decode(t, rec, &started)
		f.idp.expect(t, started.AuthorizeURL, code, userInfo{Subject: "g-" + a.ID.String(), Email: a.Email, EmailVerified: true})
		target, q := redirectQuery(t, browse(t, f.public, http.MethodGet, "/social/google/callback?state="+url.QueryEscape(stateOf(started.AuthorizeURL))+"&code="+code, nil, nil))
		if target != "https://console.example.test/account/security" || q.Get("link_code") == "" {
			t.Fatalf("link callback: %s %v", target, q)
		}
		return q.Get("link_code")
	}
	b := dbtest.User(t, tenant, tenant)
	stolen := link("link-1")
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(b.ID, tenant), f.mount), http.MethodPost, "/social/link/complete", map[string]string{"code": stolen}); !strings.Contains(rec.Body.String(), errs.CodeSocialLinkAccountMismatch) {
		t.Errorf("another account completing the link: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asA, http.MethodPost, "/social/link/complete", map[string]string{"code": stolen}); !strings.Contains(rec.Body.String(), errs.CodeSocialLinkCodeInvalid) {
		t.Errorf("a link code another account tried: %d %s, want spent", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asA, http.MethodPost, "/social/link/complete", map[string]string{"code": link("link-2")}); rec.Code != http.StatusOK {
		t.Fatalf("complete the link: %d %s", rec.Code, rec.Body.String())
	}
	var mine struct {
		Items []ExternalIdentity `json:"items"`
	}
	dbtest.Decode(t, dbtest.Do(t, asA, http.MethodGet, "/me/social/identities", nil), &mine)
	if len(mine.Items) != 1 || mine.Items[0].Provider != "google" {
		t.Fatalf("my identities %+v; want google", mine.Items)
	}
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(b.ID, tenant), f.mount), http.MethodDelete, "/me/social/identities/"+mine.Items[0].ID.String(), nil); rec.Code == http.StatusNoContent {
		t.Error("another account unlinked my identity")
	}
	if rec := dbtest.Do(t, asA, http.MethodDelete, "/me/social/identities/"+mine.Items[0].ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Errorf("unlink mine: %d %s", rec.Code, rec.Body.String())
	}
	if rec := browse(t, f.public, http.MethodGet, "/social/platform/providers", nil, nil); !strings.Contains(rec.Body.String(), "google") {
		t.Errorf("platform providers: %s", rec.Body.String())
	}
}
