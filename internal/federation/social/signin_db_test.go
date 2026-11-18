//go:build integration

package social

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp/oidcrptest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// identityProvider is a fake OIDC provider whose clients' secret is
// "idp-client-secret". Each authorization code it will accept is registered
// with expect.
type identityProvider struct {
	*oidcrptest.Provider
	t *testing.T
}

// newIdentityProvider starts the provider until t ends.
func newIdentityProvider(t *testing.T) *identityProvider {
	return &identityProvider{Provider: oidcrptest.New(t, "qeet", "idp-client-secret"), t: t}
}

// expect makes the provider accept code for the sign-in authURL began, with
// its PKCE challenge, as person: an ID token carrying the sign-in's nonce,
// and person as userinfo.
func (p *identityProvider) expect(t *testing.T, authURL, code string, person userInfo) {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || !strings.HasPrefix(authURL, oidcrptest.AuthorizeEndpoint+"?") || u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("nonce") == "" {
		t.Fatalf("authorization URL %q; want the provider's, with PKCE and a nonce", authURL)
	}
	client := u.Query().Get("client_id")
	claims := p.Claims(u.Query().Get("nonce"), person.Subject, person.Email)
	claims["aud"] = client
	p.Expect(code, oidcrptest.Grant{ClientID: client, Challenge: u.Query().Get("code_challenge"), IDToken: p.Sign(t, claims, nil, ""), Userinfo: person})
}

// TestOrganizationSocialSignIn checks an organization's own provider end to
// end: it is configured without its secret ever being returned; a sign-in
// completes only in the browser that began it, with PKCE, for a one-time code
// that buys a session once; the hosted flow returns to an allowed application
// signed in; and a closed organization, a suspended account, a switched-off
// provider and a provider people depend on are each refused.
func TestOrganizationSocialSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	f := newSocialFixture(t)
	organization := dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), f.mount)

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
	if rec := dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/social/providers", nil); !strings.Contains(rec.Body.String(), `"okta"`) || strings.Contains(rec.Body.String(), "idp-client-secret") {
		t.Errorf("providers: %s", rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPost, "/social/providers", map[string]string{"provider": "evil", "client_id": "x", "client_secret": "y", "discovery_url": "ftp://idp.example.test"}); rec.Code/100 != 4 {
		t.Errorf("a provider without an http discovery URL: %d, want refused", rec.Code)
	}

	// The organization chose the provider's endpoints, so it vouches only for
	// people on the organization's own domain.
	domain := dbtest.Domain(t, organization)
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	person := verified(t, member)
	start := "/social/okta/start?organization_id=" + organization.String()
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
	if n := dbtest.Count(t, `SELECT count(*) FROM account.external_identities WHERE user_id = $1 AND organization_id = $2 AND provider = 'okta'`, member.ID, organization); n != 1 {
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
	if rec := browse(t, f.public, http.MethodGet, start+"&return_to="+url.QueryEscape("https://evil.example.test/"), nil, nil); !strings.HasPrefix(rec.Header().Get("Location"), "https://login.example.test/sign-in?error=social") {
		t.Errorf("a return_to on another origin: %d %s, want refused", rec.Code, rec.Header().Get("Location"))
	}

	if _, q := redirectQuery(t, f.signIn(t, "okta", start, userInfo{Subject: "newcomer", Email: dbtest.Unique("new") + "@example.test", EmailVerified: true})); q.Get("error") != "registration_closed" {
		t.Errorf("a newcomer to a closed organization: %v, want registration_closed", q)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'social.signup_refused'`, organization); n != 1 {
		t.Errorf("%d refused sign-ups recorded, want 1", n)
	}
	suspended := dbtest.UserAt(t, dbtest.Unique("ravi")+"@"+domain, organization, organization)
	suspendedPerson := verified(t, suspended)
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
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
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/providers/okta", nil); !strings.Contains(rec.Body.String(), CodeProviderInUse) {
		t.Errorf("delete a provider people sign in with only: %d %s", rec.Code, rec.Body.String())
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodPatch, "/social/providers/okta", map[string]bool{"enabled": false}); !strings.Contains(rec.Body.String(), CodeProviderInUse) || !strings.Contains(rec.Body.String(), `"people":`) {
		t.Errorf("switch off a provider people sign in with only: %d %s, want refused with the count", rec.Code, rec.Body.String())
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
	if rec := browse(t, f.public, http.MethodGet, start, nil, nil); !strings.HasPrefix(rec.Header().Get("Location"), "https://login.example.test/sign-in?error=social") {
		t.Errorf("start with a switched-off provider: %s", rec.Header().Get("Location"))
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action LIKE 'social_provider.%'`, organization); n != 3 {
		t.Errorf("%d provider changes recorded, want created, updated and disabled", n)
	}
	other := dbtest.Organization(t)
	otherAdmin := dbtest.User(t, other, other)
	if rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(otherAdmin.ID, other), f.mount), http.MethodPatch, "/social/providers/okta", map[string]bool{"enabled": true}); rec.Code != http.StatusNotFound {
		t.Errorf("another organization switching the provider on: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(t, asAdmin, http.MethodDelete, "/social/providers/okta", nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete provider: %d %s", rec.Code, rec.Body.String())
	}
}

// TestSocialOIDCProviderProvesTheSignInWithItsIDToken checks that an OpenID
// Connect provider signs someone in only with an ID token its published key
// signed, from its issuer, for this client, carrying the sign-in's nonce,
// about the subject its userinfo names.
func TestSocialOIDCProviderProvesTheSignInWithItsIDToken(t *testing.T) {
	f := newSocialFixture(t)
	organization := dbtest.Organization(t)
	addProvider(t, f, organization, "okta")
	member := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+dbtest.Domain(t, organization), organization, organization)
	person := verified(t, member)
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	start := "/social/okta/start?organization_id=" + organization.String()
	// answer runs a sign-in, the provider answering with the ID token token
	// makes of the sign-in's nonce ("" for none).
	answer := func(token func(nonce string) string) *httptest.ResponseRecorder {
		t.Helper()
		begun := browse(t, f.public, http.MethodGet, start, nil, nil)
		u, err := url.Parse(begun.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		code := uuid.NewString()
		f.idp.Expect(code, oidcrptest.Grant{Challenge: q.Get("code_challenge"), IDToken: token(q.Get("nonce")), Userinfo: person})
		return browse(t, f.public, http.MethodGet, "/social/okta/callback?state="+url.QueryEscape(q.Get("state"))+"&code="+code, begun.Result().Cookies(), nil)
	}
	// signed returns a token changed by change, signed by signer under kid (nil: the provider's key).
	signed := func(change func(jwt.MapClaims), signer *rsa.PrivateKey, kid string) func(string) string {
		return func(nonce string) string {
			claims := f.idp.Claims(nonce, person.Subject, person.Email)
			if change != nil {
				change(claims)
			}
			if signer == nil {
				return f.idp.Sign(t, claims, nil, "")
			}
			return f.idp.Sign(t, claims, signer, kid)
		}
	}
	signedIn := func(rec *httptest.ResponseRecorder) bool {
		u, err := url.Parse(rec.Header().Get("Location"))
		return err == nil && rec.Code == http.StatusFound && u.Path == "/auth/social/callback" && u.Query().Get("code") != ""
	}
	if rec := answer(signed(nil, nil, "")); !signedIn(rec) {
		t.Fatalf("a correct ID token: %d %s, want signed in", rec.Code, rec.Header().Get("Location"))
	}
	for name, token := range map[string]func(string) string{
		"signed by another key":        signed(nil, stranger, "key-1"),
		"from another issuer":          signed(func(c jwt.MapClaims) { c["iss"] = "https://evil.example.test" }, nil, ""),
		"for another client":           signed(func(c jwt.MapClaims) { c["aud"] = "other-client" }, nil, ""),
		"with another sign-in's nonce": signed(func(c jwt.MapClaims) { c["nonce"] = "someone-elses" }, nil, ""),
		"about another subject":        signed(func(c jwt.MapClaims) { c["sub"] = "someone-else" }, nil, ""),
		"left out":                     func(string) string { return "" },
	} {
		if rec := answer(token); signedIn(rec) {
			t.Errorf("an ID token %s signed the person in", name)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_codes WHERE user_id = $1`, member.ID); n != 1 {
		t.Errorf("%d login codes issued, want only the correct token's", n)
	}
}
