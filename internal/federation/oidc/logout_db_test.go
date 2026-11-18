//go:build integration

package oidc

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
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

// TestIntrospectionReportsInactiveAfterSignOut checks that an application's
// access token names the hosted-login session it was issued in and introspects
// inactive once that session is signed out; that a session which only expired
// leaves a token renewed from its grant active; and that a device grant's
// token, from no session, names none and stays active.
func TestIntrospectionReportsInactiveAfterSignOut(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t, func(d *Deps, sessions *auth.Service) { d.SessionLive = sessions.SessionLive })
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClientWith(t, p.svc, CreateClientInput{
		OrganizationID: organization, GrantTypes: []string{"authorization_code", "refresh_token", grantTypeDeviceCode},
	})
	active := func(token string) bool {
		t.Helper()
		out, err := p.svc.Introspect(ctx, client.ClientID, secret, token, "")
		if err != nil {
			t.Fatalf("introspect: %v", err)
		}
		return out["active"] == true
	}
	sid := func(token string) uuid.UUID {
		t.Helper()
		claims, err := p.svc.issuer.VerifyAccessAnyAudience(token)
		if err != nil {
			t.Fatal(err)
		}
		return claims.SessionID
	}

	cookie, sessionID := p.signIn(t, person.ID)
	issued := signInThrough(t, p, client, secret, person.ID, sessionID)
	if got := sid(issued.AccessToken); got != sessionID {
		t.Errorf("access token sid %v, want the hosted-login session %v", got, sessionID)
	}
	if !active(issued.AccessToken) {
		t.Fatal("a signed-in application's access token introspects inactive")
	}
	if err := p.sessions.RevokeLoginSession(ctx, cookie.Value); err != nil {
		t.Fatal(err)
	}
	if active(issued.AccessToken) {
		t.Error("the application's access token still introspects active after its sign-in was signed out")
	}

	// The clean-up of expired sessions deletes the row but leaves the grant.
	_, sessionID = p.signIn(t, person.ID)
	issued = signInThrough(t, p, client, secret, person.ID, sessionID)
	if _, err := dbtest.Pool(t).Exec(ctx, `DELETE FROM auth.login_sessions WHERE id = $1`, sessionID); err != nil {
		t.Fatal(err)
	}
	renewed, err := p.svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("refresh after the session expired: %v", err)
	}
	if got := sid(renewed.AccessToken); got != sessionID || !active(renewed.AccessToken) {
		t.Errorf("a token renewed after its session expired: sid %v (want %v), active %t; want active", got, sessionID, active(renewed.AccessToken))
	}

	raw, userCode, _, err := p.svc.DeviceAuthorize(ctx, client.ClientID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.svc.DecideDevice(ctx, person.ID, userCode, true, deviceIP); err != nil {
		t.Fatal(err)
	}
	device, err := p.svc.DeviceToken(ctx, client.ClientID, secret, raw, deviceIP)
	if err != nil {
		t.Fatal(err)
	}
	if got := sid(device.AccessToken); got != uuid.Nil || !active(device.AccessToken) {
		t.Errorf("a device grant's token: sid %v, active %t; want no sid, active", got, active(device.AccessToken))
	}
}

// TestRPInitiatedLogout checks that without an ID token hint the person confirms
// a sign-out for their own session, that a hint naming someone else is refused,
// and that a sign-out ends the session and its grants, clears the cookie, sends
// a signed back-channel notice and continues only to a registered address.
func TestRPInitiatedLogout(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t, func(d *Deps, _ *auth.Service) { d.Egress = egress.DevelopmentPolicy() })
	notices := make(chan url.Values, 4)
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		notices <- r.PostForm
	}))
	t.Cleanup(rp.Close)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	someone := dbtest.User(t, organization, organization)
	const signedOut = "https://app.example.test/signed-out"
	client, secret := registerClientWith(t, p.svc, CreateClientInput{
		OrganizationID: organization, PostLogoutURIs: []string{signedOut},
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
	if to != loginBase+"/sign-out" || ticket == "" || q.Get("post_logout_redirect_uri") != signedOut || q.Get("state") != "s-1" || !live(cookie) {
		t.Fatalf("sign-out without a hint: sent to %s %v, want the hosted confirmation with the session kept", to, q)
	}
	confirmed := logout + "&logout_confirmation=" + url.QueryEscape(ticket)
	if to, _ := redirected(t, browse(t, p.public, http.MethodGet, confirmed, someoneCookie, nil)); to != loginBase+"/sign-out" || !live(someoneCookie) {
		t.Errorf("another session's confirmation: sent to %s, want to confirm again", to)
	}
	rec := browse(t, p.public, http.MethodGet, "/oauth/logout?id_token_hint="+url.QueryEscape(someoneHint), cookie, nil)
	if got, _ := decodeTokenError(t, rec); got != "invalid_request" || !live(cookie) {
		t.Errorf("a hint naming someone else: %d %s, want invalid_request with the session kept", rec.Code, got)
	}

	rec = browse(t, p.public, http.MethodGet, confirmed, cookie, nil)
	to, q = redirected(t, rec)
	frontchannel := "https://app.example.test/frontchannel?iss=" + p.svc.issuer.JWTIssuer() + "&sid=" + sessionID.String()
	if to != loginBase+"/sign-out/done" || !slices.Equal(q["frontchannel_logout"], []string{frontchannel}) || q.Get("continue") == "" {
		t.Fatalf("confirmed sign-out: sent to %s %v, want the signed-out page with the front-channel page and a continuation", to, q)
	}
	if !slices.ContainsFunc(rec.Result().Cookies(), func(c *http.Cookie) bool { return c.Name == auth.LoginSessionCookie && c.MaxAge < 0 }) {
		t.Error("the sign-out didn't clear the session cookie")
	}
	if live(cookie) {
		t.Error("the session outlived the sign-out")
	}
	if _, err := p.svc.RefreshToken(ctx, client.ClientID, secret, issued.RefreshToken, ""); !errors.Is(err, ErrRefreshTokenRevoked) {
		t.Errorf("refresh a grant of the ended session: %v, want %v", err, ErrRefreshTokenRevoked)
	}
	to, q = redirected(t, browse(t, p.public, http.MethodGet, "/oauth/logout/continue?ticket="+url.QueryEscape(q.Get("continue")), nil, nil))
	if to != signedOut || q.Get("state") != "s-1" {
		t.Errorf("continue: sent to %s %v, want the registered post-logout address with the state", to, q)
	}
	if to, _ := redirected(t, browse(t, p.public, http.MethodGet, "/oauth/logout/continue?ticket="+url.QueryEscape(ticket), nil, nil)); to != loginBase+"/sign-out/done" {
		t.Errorf("continue with a confirmation ticket: sent to %s, want the signed-out page", to)
	}

	// The person's own hint signs out at once; an unregistered address isn't followed.
	hint := signInThrough(t, p, client, secret, someone.ID, someoneSession).IDToken
	unregistered := "/oauth/logout?" + url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {"https://evil.example.test/"}}.Encode()
	if to, q := redirected(t, browse(t, p.public, http.MethodGet, unregistered, someoneCookie, nil)); to != loginBase+"/sign-out/done" || q.Get("continue") != "" || live(someoneCookie) {
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
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.oidc_logout_deliveries WHERE organization_id = $1 AND delivered_at IS NOT NULL`, organization); n != 2 {
		t.Errorf("%d notices marked delivered, want 2", n)
	}
}

// TestLogoutHintMustBeAnIDToken checks that a sign-out skips its confirmation
// only for an ID token this server issued to a registered application for the
// session's person: every other token it signs, naming the session or not, is
// refused with invalid_request and the session stays.
func TestLogoutHintMustBeAnIDToken(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organization := dbtest.Organization(t)
	person := dbtest.User(t, organization, organization)
	client, secret := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organization})
	must := func(raw string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sign := func(claims jwt.MapClaims) string {
		t.Helper()
		claims["iss"] = p.svc.issuer.JWTIssuer()
		return must(p.svc.issuer.Sign(claims))
	}
	issued := func(raw string, _ time.Time, err error) string { return must(raw, err) }
	live := func(c *http.Cookie) bool {
		_, err := p.sessions.ResolveLoginSession(ctx, c.Value)
		return err == nil
	}
	for name, hint := range map[string]func(session uuid.UUID) string{
		"a forced sign-in's login_after marker": func(uuid.UUID) string { return must(p.svc.loginAfterMarker(time.Now())) },
		"a sign-out continuation ticket": func(uuid.UUID) string {
			return must(p.svc.logoutContinuation("https://app.example.test/"))
		},
		"the session's own sign-out confirmation": func(sid uuid.UUID) string { return must(p.svc.logoutConfirmation(sid)) },
		"the person's access token": func(sid uuid.UUID) string {
			return issued(p.svc.issuer.IssueAccess(person.ID, organization, sid, ""))
		},
		"an application's access token": func(sid uuid.UUID) string {
			return issued(p.svc.issuer.IssueClientAccess(tokens.ClientAccess{UserID: person.ID, OrganizationID: organization, SessionID: sid, ClientID: client.ClientID}))
		},
		"a back-channel logout token": func(sid uuid.UUID) string { return must(p.notices.logoutToken(client.ClientID, person.ID, sid)) },
		"a token with no subject": func(sid uuid.UUID) string {
			return sign(jwt.MapClaims{"aud": client.ClientID, "sid": sid.String()})
		},
		"a token with no audience": func(sid uuid.UUID) string {
			return sign(jwt.MapClaims{"sub": person.ID.String(), "sid": sid.String()})
		},
		"a token for an unregistered application": func(sid uuid.UUID) string {
			return sign(jwt.MapClaims{"sub": person.ID.String(), "aud": "no-such-client", "sid": sid.String()})
		},
		"a token of another type": func(sid uuid.UUID) string {
			return sign(jwt.MapClaims{"sub": person.ID.String(), "aud": client.ClientID, "sid": sid.String(), "typ": "other"})
		},
	} {
		cookie, sessionID := p.signIn(t, person.ID)
		rec := browse(t, p.public, http.MethodGet, "/oauth/logout?id_token_hint="+url.QueryEscape(hint(sessionID)), cookie, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400 invalid_request", name, rec.Code)
		} else if got, _ := decodeTokenError(t, rec); got != "invalid_request" {
			t.Errorf("%s: %s, want invalid_request", name, got)
		}
		if !live(cookie) {
			t.Errorf("%s ended the session", name)
		}
	}

	// The person's own ID token still signs out at once.
	cookie, sessionID := p.signIn(t, person.ID)
	idToken := signInThrough(t, p, client, secret, person.ID, sessionID).IDToken
	if to, _ := redirected(t, browse(t, p.public, http.MethodGet, "/oauth/logout?id_token_hint="+url.QueryEscape(idToken), cookie, nil)); to != loginBase+"/sign-out/done" || live(cookie) {
		t.Errorf("the person's ID token: sent to %s, want signed out to the signed-out page", to)
	}
}

// TestSignOutNoticesStayInTheirOrganization checks that when one hosted-login
// session signed in to two organizations' applications, the record of telling
// them of the sign-out is kept by each organization and names only its own.
func TestSignOutNoticesStayInTheirOrganization(t *testing.T) {
	ctx := dbtest.Context(t)
	p := newProvider(t)
	organizationA, organizationB := dbtest.Organization(t), dbtest.Organization(t)
	person := dbtest.User(t, organizationA, organizationA, organizationB)
	appA, secretA := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organizationA, BackchannelLogoutURI: "http://127.0.0.1:9/a"})
	appB, secretB := registerClientWith(t, p.svc, CreateClientInput{OrganizationID: organizationB, BackchannelLogoutURI: "http://127.0.0.1:9/b"})
	cookie, sessionID := p.signIn(t, person.ID)
	signInThrough(t, p, appA, secretA, person.ID, sessionID)
	signInThrough(t, p, appB, secretB, person.ID, sessionID)
	if _, err := p.sessions.EndLoginSession(ctx, auth.EndLoginSessionInput{Cookie: cookie.Value, InitiatedBy: auth.SignOutByHostedLogin}); err != nil {
		t.Fatalf("sign out: %v", err)
	}

	for _, tc := range []struct {
		organization uuid.UUID
		own, foreign string
	}{{organizationA, appA.ClientID, appB.ClientID}, {organizationB, appB.ClientID, appA.ClientID}} {
		const naming = `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'oidc.sign_out_notified'
			AND metadata::text LIKE '%' || $2 || '%'`
		if n := dbtest.Count(t, naming, tc.organization, tc.foreign); n != 0 {
			t.Errorf("organization %s's audit names another organization's application %d times", tc.organization, n)
		}
		if n := dbtest.Count(t, naming, tc.organization, tc.own); n != 1 {
			t.Errorf("organization %s's audit records the notice to its application %d times, want once", tc.organization, n)
		}
	}
}
