//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestSigningOutTellsTheApplications pins sign-out notices (OIDC Back- and
// Front-Channel Logout): a sign-out with neither id_token_hint nor
// confirmation ends nothing and asks first; a hint for another sign-in is
// refused; a sign-out tells each application in the session (a signed logout
// token naming the session, delivered server to server and retried, a failure
// recorded; its front-channel page given to the signed-out page, which then
// continues through a signed ticket); it is audited; discovery says so.
func TestSigningOutTellsTheApplications(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	issuer := mustIssuer()
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	svc := oidc.NewService(testPool, issuer)
	svc.SetLogoutHTTPClient(egress.DevelopmentPolicy())
	authSvc.SetSignOutNotifier(svc)
	tenantID := createTenant(t, ctx, uniqueSlug("logout"))
	redirect := "https://app.example/cb"
	postLogout := "https://app.example/bye"

	var mu sync.Mutex
	var received []string
	failing := false
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		if failing {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		received = append(received, r.Form.Get("logout_token"))
	}))
	t.Cleanup(rp.Close)

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	client, secret, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", Type: "confidential", RedirectURIs: []string{redirect},
		PostLogoutURIs: []string{postLogout}, GrantTypes: []string{"authorization_code", "refresh_token"},
		BackchannelLogoutURI: rp.URL + "/backchannel", FrontchannelLogoutURI: "https://app.example/frontchannel",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	h := &oidc.Handler{Service: svc, Sessions: authSvc, LoginBaseURL: "http://login.test"}
	router := chi.NewRouter()
	router.Route("/v1", h.MountBrowser)
	h.MountPublic(router)

	// signIn opens a hosted-login session and signs the person in to the
	// application in it, returning the cookie, the session and the ID token.
	signIn := func(t *testing.T) (string, string, string) {
		t.Helper()
		id := createUserInTenant(t, ctx, tenantID)
		addTenantMembership(t, ctx, id, tenantID)
		cookie, err := authSvc.CreateLoginSession(ctx, id, "198.51.100.7", "browser")
		if err != nil {
			t.Fatal(err)
		}
		sid := loginSessionID(t, ctx, cookie)
		code, _, err := svc.AuthorizeInLoginSession(ctx, oidc.AuthorizeInput{
			LoginSessionID: sid, UserID: id, ClientID: client.ClientID, RedirectURI: redirect, Scopes: []string{"openid"},
			Nonce: testNonce, CodeChallenge: testChallenge, CodeChallengeMethod: "S256",
		})
		if err != nil {
			t.Fatal(err)
		}
		out, err := svc.ExchangeCode(ctx, client.ClientID, secret, code, redirect, testVerifier, "")
		if err != nil {
			t.Fatal(err)
		}
		return cookie, sid.String(), out.IDToken
	}

	t.Run("a sign-out with no hint and no confirmation ends nothing and asks first", func(t *testing.T) {
		cookie, _, _ := signIn(t)
		loc := get(router, "/v1/oauth/logout?"+url.Values{"client_id": {client.ClientID}}.Encode(), cookie)
		if loc == nil || loc.Host != "login.test" || loc.Path != "/logout" || loc.Query().Get("logout_confirmation") == "" {
			t.Fatalf("plain sign-out link: redirect %v, want the hosted confirmation page", loc)
		}
		if loc2 := get(router, "/v1/oauth/authorize?"+url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirect},
			"scope": {"openid"}, "response_type": {"code"}, "nonce": {testNonce}, "code_challenge": {testChallenge},
			"code_challenge_method": {"S256"}, "prompt": {"none"}}.Encode(), cookie); loc2 == nil || loc2.Query().Get("error") == "login_required" {
			t.Fatalf("the session ended without confirmation: %v", loc2)
		}
		// Confirmed: the session ends, and the signed-out page gets the
		// application's front-channel page naming the session.
		back := get(router, "/v1/oauth/logout?"+loc.Query().Encode(), cookie)
		if back == nil || back.Path != "/logged-out" || !strings.Contains(strings.Join(back.Query()["frontchannel_logout"], " "), "https://app.example/frontchannel?iss=") {
			t.Fatalf("confirmed sign-out: redirect %v, want the signed-out page with the front-channel page", back)
		}
	})

	t.Run("a hint for another sign-in is refused, and the session stays", func(t *testing.T) {
		cookie, _, _ := signIn(t)
		_, _, otherHint := signIn(t)
		req := httptest.NewRequest(http.MethodGet, "/v1/oauth/logout?"+url.Values{"id_token_hint": {otherHint}}.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid_request") {
			t.Fatalf("another sign-in's hint: %d %s, want 400 invalid_request", rr.Code, rr.Body.String())
		}
	})

	t.Run("a sign-out tells the application server to server, naming the session", func(t *testing.T) {
		mu.Lock()
		received = nil
		mu.Unlock()
		cookie, sid, hint := signIn(t)
		q := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {postLogout}, "state": {"s9"}}
		loc := get(router, "/v1/oauth/logout?"+q.Encode(), cookie)
		if loc == nil || loc.Path != "/logged-out" || loc.Query().Get("continue") == "" {
			t.Fatalf("sign-out with a hint: redirect %v, want the signed-out page with a continuation", loc)
		}
		// The signed-out page continues to the validated address.
		next := get(router, "/v1/oauth/logout/continue?"+url.Values{"ticket": {loc.Query().Get("continue")}}.Encode(), "")
		if next == nil || next.String() != postLogout+"?state=s9" {
			t.Fatalf("continue: redirect %v, want %s?state=s9", next, postLogout)
		}
		if bogus := get(router, "/v1/oauth/logout/continue?ticket=forged", ""); bogus == nil || bogus.Path != "/logged-out" {
			t.Fatalf("continue with a forged ticket: redirect %v, want the signed-out page", bogus)
		}

		n, err := svc.DeliverLogoutNotices(ctx)
		if err != nil || n < 1 {
			t.Fatalf("deliver: %d, %v", n, err)
		}
		mu.Lock()
		defer mu.Unlock()
		found := false
		for _, tok := range received {
			claims, err := issuer.VerifySignedAnyTime(tok)
			if err != nil {
				t.Fatalf("logout token doesn't verify: %v", err)
			}
			events, _ := claims["events"].(map[string]any)
			if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; ok && claims["sid"] == sid && claims["aud"] == client.ClientID {
				found = true
			}
		}
		if !found {
			t.Fatalf("no logout token for session %s among %d delivered", sid, len(received))
		}
		var audited int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE action = 'oidc.sign_out_notified'
			AND resource_id = $1::uuid AND metadata->'backchannel' ? $2`, sid, client.ClientID).Scan(&audited); err != nil || audited != 1 {
			t.Fatalf("sign-out notice audit rows = %d (%v), want 1", audited, err)
		}
	})

	t.Run("a notice that keeps failing is retried, then recorded", func(t *testing.T) {
		mu.Lock()
		failing = true
		mu.Unlock()
		t.Cleanup(func() { mu.Lock(); failing = false; mu.Unlock() })
		cookie, _, hint := signIn(t)
		if loc := get(router, "/v1/oauth/logout?"+url.Values{"id_token_hint": {hint}}.Encode(), cookie); loc == nil {
			t.Fatal("sign-out didn't redirect")
		}
		for range 5 {
			if _, err := testPool.Exec(ctx, `UPDATE auth.oidc_logout_deliveries SET next_attempt_at = NOW()
				WHERE client_id = $1 AND delivered_at IS NULL AND failed_at IS NULL`, client.ClientID); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.DeliverLogoutNotices(ctx); err != nil {
				t.Fatal(err)
			}
		}
		var failed, audited int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.oidc_logout_deliveries WHERE client_id = $1 AND failed_at IS NOT NULL AND attempts = 5`,
			client.ClientID).Scan(&failed); err != nil {
			t.Fatal(err)
		}
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'oidc.backchannel_logout_failed'`,
			tenantID).Scan(&audited); err != nil {
			t.Fatal(err)
		}
		if failed != 1 || audited != 1 {
			t.Fatalf("after five failed attempts: %d delivery marked failed, %d audit row(s); want 1 and 1", failed, audited)
		}
	})
}
