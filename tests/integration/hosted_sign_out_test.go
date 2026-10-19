//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Signing out of the hosted login ends that browser's sign-in and everything
// it started: the applications it signed the person in to lose their refresh
// grants, and codes it minted but no application has redeemed yet can no
// longer be redeemed. Other browsers, API sessions and grants started
// elsewhere are left alone, and the sign-out is recorded. Both ways in are
// covered: the hosted login's own sign-out (DELETE /v1/auth/session) and an
// application's sign-out request (/v1/oauth/logout).

type hostedSignOutFixture struct {
	svc           *auth.Service
	oidc          *oidc.Service
	router        http.Handler
	tenantID      uuid.UUID
	clientID      string
	secret        string
	redirectURI   string
	postLogoutURI string
}

func newHostedSignOutFixture(t *testing.T, ctx context.Context) *hostedSignOutFixture {
	t.Helper()
	issuer := mustIssuer()
	f := &hostedSignOutFixture{
		svc:           auth.NewService(testPool, user.NewRepository(testPool), issuer),
		oidc:          oidc.NewService(testPool, issuer),
		tenantID:      createTenant(t, ctx, uniqueSlug("signout")),
		redirectURI:   "https://app.example/cb",
		postLogoutURI: "https://app.example/signed-out",
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := f.oidc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: f.tenantID, Name: "RP", RedirectURIs: []string{f.redirectURI},
		PostLogoutURIs: []string{f.postLogoutURI},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	f.clientID, f.secret = client.ClientID, secret

	authH := &auth.Handler{Service: f.svc, Validate: validator.New()}
	oidcH := &oidc.Handler{Service: f.oidc, Sessions: f.svc, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		authH.Mount(r)
		oidcH.MountBrowser(r)
	})
	f.router = r
	return f
}

// newMember creates a member of the fixture's organisation who has already
// consented to the application, so authorizing goes straight back to it.
func (f *hostedSignOutFixture) newMember(t *testing.T, ctx context.Context) uuid.UUID {
	t.Helper()
	id := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, id, f.tenantID)
	if err := f.oidc.GrantConsent(ctx, id, f.clientID, []string{"openid"}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}
	return id
}

// signIn opens a hosted-login session in a new browser and returns its cookie.
func (f *hostedSignOutFixture) signIn(t *testing.T, ctx context.Context, userID uuid.UUID) string {
	t.Helper()
	raw, err := f.svc.CreateLoginSession(ctx, userID, "198.51.100.7", "browser")
	if err != nil {
		t.Fatalf("open hosted-login session: %v", err)
	}
	return raw
}

// authorize runs the browser authorize endpoint with the cookie and returns the
// code the application receives.
func (f *hostedSignOutFixture) authorize(t *testing.T, cookie string) string {
	t.Helper()
	q := url.Values{"client_id": {f.clientID}, "redirect_uri": {f.redirectURI}, "scope": {"openid"}, "state": {"s"}, "code_challenge": {testChallenge}, "code_challenge_method": {"S256"}, "nonce": {testNonce}}
	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	loc, err := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusFound || err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: status %d, location %q; want a redirect carrying a code", rr.Code, rr.Header().Get("Location"))
	}
	return loc.Query().Get("code")
}

// appSignIn signs the browser in to the application, which then holds a
// refresh grant.
func (f *hostedSignOutFixture) appSignIn(t *testing.T, ctx context.Context, cookie string) *oidc.TokenResponse {
	t.Helper()
	issued, err := f.oidc.ExchangeCode(ctx, f.clientID, f.secret, f.authorize(t, cookie), f.redirectURI, testVerifier, "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("the application received no refresh token")
	}
	return issued
}

// renew trades a refresh token for the next one and returns it.
func (f *hostedSignOutFixture) renew(t *testing.T, ctx context.Context, refresh string) string {
	t.Helper()
	next, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, refresh, "")
	if err != nil {
		t.Fatalf("renew grant: %v", err)
	}
	return next.RefreshToken
}

func (f *hostedSignOutFixture) signOutOfHostedLogin(cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/v1/auth/session", nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

func (f *hostedSignOutFixture) signOutFromApp(cookie string, q url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/v1/oauth/logout?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
	}
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// loginSessionID is the id of the hosted-login session behind a cookie.
func loginSessionID(t *testing.T, ctx context.Context, cookie string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := testPool.QueryRow(ctx, `SELECT id FROM auth.login_sessions WHERE token_hash = $1`,
		tokens.HashRefresh(cookie)).Scan(&id); err != nil {
		t.Fatalf("read the hosted-login session id: %v", err)
	}
	return id
}

type signOutRecord struct {
	count    int
	tenantID *uuid.UUID
	resource *uuid.UUID
	metadata map[string]any
}

func signOutRecords(t *testing.T, ctx context.Context, userID uuid.UUID) signOutRecord {
	t.Helper()
	var rec signOutRecord
	rows, err := testPool.Query(ctx, `
		SELECT tenant_id, resource_id, metadata FROM audit.events
		WHERE actor_user_id = $1 AND action = 'auth.signed_out' AND resource_type = 'login_session'`, userID)
	if err != nil {
		t.Fatalf("read sign-out records: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		rec.count++
		if err := rows.Scan(&rec.tenantID, &rec.resource, &raw); err != nil {
			t.Fatalf("scan sign-out record: %v", err)
		}
		if err := json.Unmarshal(raw, &rec.metadata); err != nil {
			t.Fatalf("decode sign-out record: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read sign-out records: %v", err)
	}
	return rec
}

// TestSignOutEndsTheSessionAndWhatItStarted: whichever way the person signs
// out, the hosted-login session is removed and the cookie cleared as before;
// the application grant the session started — already renewed once, as a live
// application's would be — stops renewing; and a code the session minted that
// the application has not redeemed yet can no longer be redeemed.
func TestSignOutEndsTheSessionAndWhatItStarted(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	ways := map[string]func(cookie string) *httptest.ResponseRecorder{
		"from the hosted login": f.signOutOfHostedLogin,
		"from the application": func(cookie string) *httptest.ResponseRecorder {
			return f.signOutFromApp(cookie, url.Values{"client_id": {f.clientID}})
		},
	}
	for name, signOut := range ways {
		t.Run(name, func(t *testing.T) {
			me := f.newMember(t, ctx)
			browser := f.signIn(t, ctx, me)
			refresh := f.renew(t, ctx, f.appSignIn(t, ctx, browser).RefreshToken)
			pendingCode := f.authorize(t, browser)

			rr := signOut(browser)
			if rr.Code != http.StatusNoContent && rr.Code != http.StatusFound {
				t.Fatalf("sign-out status = %d, want it to succeed", rr.Code)
			}
			if !clearsHostedLoginCookie(rr.Result().Header.Values("Set-Cookie")) {
				t.Fatal("the browser was not told to drop the hosted-login cookie")
			}
			if _, err := f.svc.ResolveLoginSession(ctx, browser); err == nil {
				t.Fatal("the hosted-login session still resolves after sign-out")
			}
			if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, refresh, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
				t.Fatalf("the application's grant still renews after sign-out: err = %v", err)
			}
			if _, err := f.oidc.ExchangeCode(ctx, f.clientID, f.secret, pendingCode, f.redirectURI, testVerifier, ""); !errors.Is(err, errs.ErrOIDCAuthCodeUsed) {
				t.Fatalf("a code minted before sign-out can still be redeemed: err = %v", err)
			}
		})
	}
}

// TestSignOutEndsOnlyThatBrowser: a person signed in from two browsers, each
// signed in to the application, and with an API session. Signing out of one
// browser ends that browser's sign-in and its grant only.
func TestSignOutEndsOnlyThatBrowser(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	me := f.newMember(t, ctx)
	laptop, phone := f.signIn(t, ctx, me), f.signIn(t, ctx, me)
	laptopGrant, phoneGrant := f.appSignIn(t, ctx, laptop), f.appSignIn(t, ctx, phone)
	if _, err := f.svc.IssuePair(ctx, me, uuid.Nil, "198.51.100.7", "console", "password"); err != nil {
		t.Fatalf("open API session: %v", err)
	}

	if rr := f.signOutOfHostedLogin(laptop); rr.Code != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, want 204", rr.Code)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, laptopGrant.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Fatalf("the signed-out browser's grant still renews: err = %v", err)
	}
	if _, err := f.svc.ResolveLoginSession(ctx, phone); err != nil {
		t.Fatalf("the other browser was signed out too: %v", err)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, phoneGrant.RefreshToken, ""); err != nil {
		t.Fatalf("the other browser's grant stopped renewing: %v", err)
	}
	if n := liveSessionCount(t, ctx, me); n != 1 {
		t.Fatalf("live API sessions = %d, want the one left alone", n)
	}
}

// TestSignOutIsRecorded: a completed sign-out leaves one record naming the
// session, the application that asked for it (or the hosted login itself) and
// what was ended.
func TestSignOutIsRecorded(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)

	t.Run("asked by an application", func(t *testing.T) {
		me := f.newMember(t, ctx)
		browser := f.signIn(t, ctx, me)
		f.appSignIn(t, ctx, browser)
		f.authorize(t, browser) // a code left unredeemed
		session := loginSessionID(t, ctx, browser)

		f.signOutFromApp(browser, url.Values{"client_id": {f.clientID}})
		rec := signOutRecords(t, ctx, me)
		if rec.count != 1 {
			t.Fatalf("sign-out records = %d, want 1", rec.count)
		}
		if rec.resource == nil || *rec.resource != session {
			t.Fatalf("the record names session %v, want %v", rec.resource, session)
		}
		if rec.tenantID == nil || *rec.tenantID != f.tenantID {
			t.Fatalf("the record is filed under organisation %v, want %v", rec.tenantID, f.tenantID)
		}
		want := map[string]any{
			"initiated_by": "application", "client_id": f.clientID,
			"revoked_app_grants": float64(1), "expired_authorization_codes": float64(1),
		}
		for k, v := range want {
			if rec.metadata[k] != v {
				t.Errorf("record %s = %v, want %v (record: %v)", k, rec.metadata[k], v, rec.metadata)
			}
		}
	})

	t.Run("from the hosted login", func(t *testing.T) {
		me := f.newMember(t, ctx)
		browser := f.signIn(t, ctx, me)
		f.signOutOfHostedLogin(browser)
		rec := signOutRecords(t, ctx, me)
		if rec.count != 1 {
			t.Fatalf("sign-out records = %d, want 1", rec.count)
		}
		if rec.metadata["initiated_by"] != "hosted_login" || rec.metadata["client_id"] != nil {
			t.Fatalf("record = %v, want it to name the hosted login and no application", rec.metadata)
		}
		if rec.metadata["revoked_app_grants"] != float64(0) {
			t.Fatalf("record revoked_app_grants = %v, want 0", rec.metadata["revoked_app_grants"])
		}
	})

	t.Run("an application id that is not registered is not recorded as the initiator", func(t *testing.T) {
		me := f.newMember(t, ctx)
		browser := f.signIn(t, ctx, me)
		f.signOutFromApp(browser, url.Values{"client_id": {"no-such-app"}})
		rec := signOutRecords(t, ctx, me)
		if rec.count != 1 || rec.metadata["client_id"] != nil || rec.metadata["initiated_by"] != "application" {
			t.Fatalf("record = %+v, want one record without a client_id", rec)
		}
	})
}

// TestSignOutWithNoSessionEndsNothing: a sign-out request that does not carry
// the browser's own hosted-login session — no cookie, or a value that is no
// session — ends nothing, even when it names the application and the person
// holds grants and sessions. Nothing is recorded, and the response is the same
// as a real sign-out's.
func TestSignOutWithNoSessionEndsNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	me := f.newMember(t, ctx)
	browser := f.signIn(t, ctx, me)
	grant := f.appSignIn(t, ctx, browser)

	for name, cookie := range map[string]string{"no cookie": "", "not a session": "made-up-value"} {
		if rr := f.signOutOfHostedLogin(cookie); rr.Code != http.StatusNoContent {
			t.Fatalf("%s: hosted sign-out status = %d, want 204", name, rr.Code)
		}
		rr := f.signOutFromApp(cookie, url.Values{"client_id": {f.clientID}, "post_logout_redirect_uri": {f.postLogoutURI}})
		if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), f.postLogoutURI) {
			t.Fatalf("%s: application sign-out = %d %q, want the usual redirect", name, rr.Code, rr.Header().Get("Location"))
		}
	}
	if _, err := f.svc.ResolveLoginSession(ctx, browser); err != nil {
		t.Fatalf("the person's hosted-login session was ended: %v", err)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, grant.RefreshToken, ""); err != nil {
		t.Fatalf("the person's grant was ended: %v", err)
	}
	if rec := signOutRecords(t, ctx, me); rec.count != 0 {
		t.Fatalf("sign-out records = %d, want none", rec.count)
	}
}

// TestSignOutRedirectsAsBefore: the post-sign-out redirect is unchanged — to a
// registered address of the named application, carrying state; otherwise to
// the hosted signed-out page.
func TestSignOutRedirectsAsBefore(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	cases := []struct {
		name string
		q    url.Values
		want string
	}{
		{"registered address", url.Values{"client_id": {f.clientID}, "post_logout_redirect_uri": {f.postLogoutURI}, "state": {"st"}}, f.postLogoutURI + "?state=st"},
		{"registered address, no state", url.Values{"client_id": {f.clientID}, "post_logout_redirect_uri": {f.postLogoutURI}}, f.postLogoutURI},
		{"address not registered", url.Values{"client_id": {f.clientID}, "post_logout_redirect_uri": {"https://evil.example/"}}, "http://login.test/logged-out"},
		{"address without an application", url.Values{"post_logout_redirect_uri": {f.postLogoutURI}}, "http://login.test/logged-out"},
		{"nothing supplied", url.Values{}, "http://login.test/logged-out"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			browser := f.signIn(t, ctx, f.newMember(t, ctx))
			rr := f.signOutFromApp(browser, c.q)
			if rr.Code != http.StatusFound || rr.Header().Get("Location") != c.want {
				t.Fatalf("redirect = %d %q, want 302 %q", rr.Code, rr.Header().Get("Location"), c.want)
			}
		})
	}
}

// TestSigningInAgainStartsAfresh: after signing out, signing straight back in
// gives a new session; the grant the old one started stays ended, and the
// application signs in again with a new grant.
func TestSigningInAgainStartsAfresh(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	me := f.newMember(t, ctx)
	first := f.signIn(t, ctx, me)
	firstSession := loginSessionID(t, ctx, first)
	oldGrant := f.appSignIn(t, ctx, first)
	f.signOutOfHostedLogin(first)

	again := f.signIn(t, ctx, me)
	if loginSessionID(t, ctx, again) == firstSession {
		t.Fatal("signing in again reused the ended session")
	}
	newGrant := f.appSignIn(t, ctx, again)
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, oldGrant.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Fatalf("the old grant works again after signing back in: err = %v", err)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, newGrant.RefreshToken, ""); err != nil {
		t.Fatalf("the new grant does not renew: %v", err)
	}
}

// signOutWhileHeld runs the sign-out while another transaction holds row locks
// the sign-out has to wait for, commits that transaction once the sign-out is waiting on them (or has finished), and
// returns the sign-out's status.
func (f *hostedSignOutFixture) signOutWhileHeld(t *testing.T, ctx context.Context, cookie string, commit func() error, table string) int {
	t.Helper()
	done := make(chan int, 1)
	go func() { done <- f.signOutOfHostedLogin(cookie).Code }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := testPool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			               WHERE wait_event_type = 'Lock' AND query ILIKE '%' || $1 || '%')`, table).Scan(&waiting); err != nil {
			t.Fatalf("watch locks: %v", err)
		}
		if waiting {
			break
		}
		select {
		case code := <-done:
			if err := commit(); err != nil {
				t.Fatalf("commit: %v", err)
			}
			return code
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the sign-out neither finished nor waited")
		}
	}
	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	select {
	case code := <-done:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("the sign-out did not finish after the other transaction committed")
	}
	return 0
}

// TestSignOutAlsoEndsAGrantRenewedWhileItRuns: an application renewing its
// grant at the moment of sign-out writes the next token after the sign-out has
// started; that token is ended too.
func TestSignOutAlsoEndsAGrantRenewedWhileItRuns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	me := f.newMember(t, ctx)
	browser := f.signIn(t, ctx, me)
	grant := f.appSignIn(t, ctx, browser)

	// The renewal, held open mid-way exactly as the refresh grant runs it.
	renewal, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin renewal: %v", err)
	}
	defer renewal.Rollback(ctx)
	nextRaw, nextHash, err := tokens.NewRefreshToken()
	if err != nil {
		t.Fatalf("new refresh token: %v", err)
	}
	var presentedID, nextID uuid.UUID
	if err := renewal.QueryRow(ctx, `SELECT id FROM auth.oidc_refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		tokens.HashRefresh(grant.RefreshToken)).Scan(&presentedID); err != nil {
		t.Fatalf("lock presented token: %v", err)
	}
	if err := renewal.QueryRow(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, scopes, expires_at, login_session_id)
		SELECT $1, client_id, user_id, tenant_id, scopes, NOW() + INTERVAL '30 days', login_session_id
		FROM auth.oidc_refresh_tokens WHERE id = $2
		RETURNING id`, nextHash, presentedID).Scan(&nextID); err != nil {
		t.Fatalf("write the next token: %v", err)
	}
	if _, err := renewal.Exec(ctx, `UPDATE auth.oidc_refresh_tokens SET used_at = NOW(), replaced_by = $1 WHERE id = $2`, nextID, presentedID); err != nil {
		t.Fatalf("mark presented used: %v", err)
	}

	if code := f.signOutWhileHeld(t, ctx, browser, func() error { return renewal.Commit(ctx) }, "oidc_refresh_tokens"); code != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, want 204", code)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, nextRaw, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Fatalf("the token renewed during the sign-out still works: err = %v", err)
	}
}

// TestSignOutAlsoEndsAGrantWhoseCodeIsBeingRedeemed: an application redeeming
// its code at the moment of sign-out writes its grant after the sign-out has
// started; that grant is ended too.
func TestSignOutAlsoEndsAGrantWhoseCodeIsBeingRedeemed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newHostedSignOutFixture(t, ctx)
	me := f.newMember(t, ctx)
	browser := f.signIn(t, ctx, me)
	code := f.authorize(t, browser)

	// The redemption, held open mid-way as the code grant runs it: the code is
	// locked and spent and the grant written in the same transaction.
	redemption, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin redemption: %v", err)
	}
	defer redemption.Rollback(ctx)
	grantRaw, grantHash, err := tokens.NewRefreshToken()
	if err != nil {
		t.Fatalf("new refresh token: %v", err)
	}
	codeHash := codes.Hash(code)
	if _, err := redemption.Exec(ctx, `SELECT 1 FROM auth.oidc_authorization_codes WHERE code_hash = $1 FOR UPDATE`, codeHash); err != nil {
		t.Fatalf("lock code: %v", err)
	}
	if _, err := redemption.Exec(ctx, `UPDATE auth.oidc_authorization_codes SET used_at = NOW() WHERE code_hash = $1`, codeHash); err != nil {
		t.Fatalf("spend code: %v", err)
	}
	if _, err := redemption.Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, scopes, expires_at, login_session_id)
		SELECT $1, client_id, user_id, tenant_id, scopes, NOW() + INTERVAL '30 days', login_session_id
		FROM auth.oidc_authorization_codes WHERE code_hash = $2`, grantHash, codeHash); err != nil {
		t.Fatalf("write the grant: %v", err)
	}

	if status := f.signOutWhileHeld(t, ctx, browser, func() error { return redemption.Commit(ctx) }, "oidc_authorization_codes"); status != http.StatusNoContent {
		t.Fatalf("sign-out status = %d, want 204", status)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, grantRaw, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Fatalf("the grant written while the sign-out ran still works: err = %v", err)
	}
}
