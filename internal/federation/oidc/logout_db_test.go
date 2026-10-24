//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// signInThrough redeems a code minted in the hosted-login session sessionID
// for userID at client, and returns the tokens.
func signInThrough(t *testing.T, p *provider, client *Client, secret string, userID, sessionID uuid.UUID) *TokenResponse {
	t.Helper()
	ctx := dbtest.Context(t)
	verifier, challenge, _ := codes.URLToken()
	code, _, err := p.svc.AuthorizeInLoginSession(ctx, AuthorizeInput{
		LoginSessionID: sessionID, UserID: userID, ClientID: client.ClientID, RedirectURI: testRedirect,
		Scopes: []string{"openid"}, Nonce: "n-1", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := p.svc.ExchangeCode(ctx, client.ClientID, secret, code, testRedirect, verifier, "")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	return issued
}

// TestRPInitiatedLogout checks that without an ID token hint the person confirms
// a sign-out for their own session, that a hint naming someone else is refused,
// and that a sign-out ends the session and its grants, clears the cookie, sends
// a signed back-channel notice and continues only to a registered address.
func TestRPInitiatedLogout(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	p.svc.SetLogoutHTTPClient(egress.DevelopmentPolicy())
	notices := make(chan url.Values, 4)
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		notices <- r.PostForm
	}))
	t.Cleanup(rp.Close)
	tenant := dbtest.Tenant(t)
	person := dbtest.User(t, tenant, tenant)
	someone := dbtest.User(t, tenant, tenant)
	const signedOut = "https://app.example.test/signed-out"
	client, secret := registerClientWith(t, p.svc, CreateClientInput{
		TenantID: tenant, PostLogoutURIs: []string{signedOut},
		BackchannelLogoutURI: rp.URL + "/backchannel", FrontchannelLogoutURI: "https://app.example.test/frontchannel",
	})
	cookie, sessionID := p.signIn(t, person.ID)
	issued := signInThrough(t, p, client, secret, person.ID, sessionID)
	someoneCookie, someoneSession := p.signIn(t, someone.ID)
	someoneHint := signInThrough(t, p, client, secret, someone.ID, someoneSession).IDToken
	logout := "/oauth/logout?" + url.Values{"client_id": {client.ClientID}, "post_logout_redirect_uri": {signedOut}, "state": {"s-1"}}.Encode()
	live := func(c *http.Cookie) bool {
		t.Helper()
		_, err := p.sessions.ResolveLoginSession(ctx, c.Value)
		return err == nil
	}

	to, q := redirected(t, browse(t, p.public, http.MethodGet, logout, cookie, nil))
	ticket := q.Get("logout_confirmation")
	if to != loginBase+"/logout" || ticket == "" || q.Get("post_logout_redirect_uri") != signedOut || q.Get("state") != "s-1" || !live(cookie) {
		t.Fatalf("sign-out without a hint: sent to %s %v, want the hosted confirmation with the session kept", to, q)
	}
	confirmed := logout + "&logout_confirmation=" + url.QueryEscape(ticket)
	if to, _ := redirected(t, browse(t, p.public, http.MethodGet, confirmed, someoneCookie, nil)); to != loginBase+"/logout" || !live(someoneCookie) {
		t.Errorf("another session's confirmation: sent to %s, want to confirm again", to)
	}
	rec := browse(t, p.public, http.MethodGet, "/oauth/logout?id_token_hint="+url.QueryEscape(someoneHint), cookie, nil)
	if got, _ := decodeTokenError(t, rec); got != "invalid_request" || !live(cookie) {
		t.Errorf("a hint naming someone else: %d %s, want invalid_request with the session kept", rec.Code, got)
	}

	rec = browse(t, p.public, http.MethodGet, confirmed, cookie, nil)
	to, q = redirected(t, rec)
	frontchannel := "https://app.example.test/frontchannel?iss=" + p.svc.issuer.JWTIssuer() + "&sid=" + sessionID.String()
	if to != loginBase+"/logged-out" || !slices.Equal(q["frontchannel_logout"], []string{frontchannel}) || q.Get("continue") == "" {
		t.Fatalf("confirmed sign-out: sent to %s %v, want the signed-out page with the front-channel page and a continuation", to, q)
	}
	if !slices.ContainsFunc(rec.Result().Cookies(), func(c *http.Cookie) bool { return c.Name == auth.LoginSessionCookie && c.MaxAge < 0 }) {
		t.Error("the sign-out didn't clear the session cookie")
	}
	if live(cookie) {
		t.Error("the session outlived the sign-out")
	}
	if _, err := p.svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Errorf("refresh a grant of the ended session: %v, want %v", err, errs.ErrOIDCRefreshTokenRevoked)
	}
	to, q = redirected(t, browse(t, p.public, http.MethodGet, "/oauth/logout/continue?ticket="+url.QueryEscape(q.Get("continue")), nil, nil))
	if to != signedOut || q.Get("state") != "s-1" {
		t.Errorf("continue: sent to %s %v, want the registered post-logout address with the state", to, q)
	}
	if to, _ := redirected(t, browse(t, p.public, http.MethodGet, "/oauth/logout/continue?ticket="+url.QueryEscape(ticket), nil, nil)); to != loginBase+"/logged-out" {
		t.Errorf("continue with a confirmation ticket: sent to %s, want the signed-out page", to)
	}

	// The person's own hint signs out at once; an unregistered address isn't followed.
	hint := signInThrough(t, p, client, secret, someone.ID, someoneSession).IDToken
	unregistered := "/oauth/logout?" + url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://evil.example.test/"}}.Encode()
	if to, q := redirected(t, browse(t, p.public, http.MethodGet, unregistered, someoneCookie, nil)); to != loginBase+"/logged-out" || q.Get("continue") != "" || live(someoneCookie) {
		t.Errorf("sign-out with the person's own hint: sent to %s %v, want signed out to the signed-out page only", to, q)
	}

	delivered, err := p.svc.DeliverLogoutNotices(ctx)
	if err != nil || delivered < 2 {
		t.Fatalf("deliver the sign-out notices: %d, %v; want both", delivered, err)
	}
	signedOutOf := map[string]string{sessionID.String(): person.ID.String(), someoneSession.String(): someone.ID.String()}
	for range 2 {
		claims, err := p.svc.issuer.VerifySigned((<-notices).Get("logout_token"))
		if err != nil {
			t.Fatalf("verify the logout token: %v", err)
		}
		events, _ := claims["events"].(map[string]any)
		sid, _ := claims["sid"].(string)
		if _, ok := events[backchannelLogoutEvent]; !ok || claims["aud"] != client.ClientID || claims["jti"] == nil || claims["nonce"] != nil ||
			signedOutOf[sid] == "" || claims["sub"] != signedOutOf[sid] {
			t.Errorf("logout token %v, want the back-channel event for the application and a session's person, without a nonce", claims)
		}
		delete(signedOutOf, sid)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_logout_deliveries WHERE tenant_id = $1 AND delivered_at IS NOT NULL`, tenant); n != 2 {
		t.Errorf("%d notices marked delivered, want 2", n)
	}
}

// TestSignOutNoticesStayInTheirOrganisation checks that when one hosted-login
// session signed in to two organisations' applications, the record of telling
// them of the sign-out is kept by each organisation and names only its own.
func TestSignOutNoticesStayInTheirOrganisation(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	tenantA, tenantB := dbtest.Tenant(t), dbtest.Tenant(t)
	person := dbtest.User(t, tenantA, tenantA, tenantB)
	appA, secretA := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenantA, BackchannelLogoutURI: "http://127.0.0.1:9/a"})
	appB, secretB := registerClientWith(t, p.svc, CreateClientInput{TenantID: tenantB, BackchannelLogoutURI: "http://127.0.0.1:9/b"})
	cookie, sessionID := p.signIn(t, person.ID)
	signInThrough(t, p, appA, secretA, person.ID, sessionID)
	signInThrough(t, p, appB, secretB, person.ID, sessionID)
	if _, err := p.sessions.EndLoginSession(ctx, auth.EndLoginSessionInput{Cookie: cookie.Value, InitiatedBy: auth.SignOutByHostedLogin}); err != nil {
		t.Fatalf("sign out: %v", err)
	}

	for _, tc := range []struct {
		tenant       uuid.UUID
		own, foreign string
	}{{tenantA, appA.ClientID, appB.ClientID}, {tenantB, appB.ClientID, appA.ClientID}} {
		const naming = `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oidc.sign_out_notified'
			AND metadata::text LIKE '%' || $2 || '%'`
		if n := dbtest.Count(t, naming, tc.tenant, tc.foreign); n != 0 {
			t.Errorf("organisation %s's audit names another organisation's application %d times", tc.tenant, n)
		}
		if n := dbtest.Count(t, naming, tc.tenant, tc.own); n != 1 {
			t.Errorf("organisation %s's audit records the notice to its application %d times, want once", tc.tenant, n)
		}
	}
}
