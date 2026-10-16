//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// "Sign out everywhere" is one self-service call that ends every way the
// caller is signed in — API and console sessions, hosted-login browser
// sessions, and the refresh grants applications hold — including the session
// the caller is using. These tests drive it through the real handler behind
// the real bearer-token middleware, next to the real browser authorize
// endpoint, so the effect is observed the way a client would observe it.

const signOutEverywherePath = "/v1/auth/sessions/revoke-all"

type signOutEverywhereFixture struct {
	svc         *auth.Service
	oidc        *oidc.Service
	issuer      *tokens.Issuer
	router      http.Handler
	tenantID    uuid.UUID
	clientID    string
	secret      string
	redirectURI string
}

func newSignOutEverywhereFixture(t *testing.T, ctx context.Context) *signOutEverywhereFixture {
	t.Helper()
	issuer := mustIssuer()
	f := &signOutEverywhereFixture{
		svc:         auth.NewService(testPool, user.NewRepository(testPool), issuer),
		oidc:        oidc.NewService(testPool, issuer),
		issuer:      issuer,
		tenantID:    createTenant(t, ctx, uniqueSlug("everywhere")),
		redirectURI: "https://app.example/cb",
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := f.oidc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: f.tenantID, Name: "RP", RedirectURIs: []string{f.redirectURI},
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
		r.Group(func(r chi.Router) {
			r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
			authH.MountAuthed(r)
		})
		oidcH.MountBrowser(r)
	})
	f.router = r
	return f
}

// signIns is everything one person is signed in with, in all three places.
type signIns struct {
	userID   uuid.UUID
	sessions []*auth.TokenPair     // API / console sessions
	browsers []string              // hosted-login cookie values
	grants   []*oidc.TokenResponse // an application's tokens, one per grant
}

// newPerson creates a member of the fixture's organisation who is signed in
// with the given number of API sessions, hosted-login browser sessions and
// application grants. The account is inserted directly (not via sign-up) so
// these tests do not depend on how sign-up checks passwords.
func (f *signOutEverywhereFixture) newPerson(t *testing.T, ctx context.Context, sessions, browsers, grants int) *signIns {
	t.Helper()
	p := &signIns{userID: createUserInTenant(t, ctx, f.tenantID)}
	addTenantMembership(t, ctx, p.userID, f.tenantID)
	for i := 0; i < sessions; i++ {
		pair, err := f.svc.IssuePair(ctx, p.userID, uuid.Nil, "198.51.100.7", fmt.Sprintf("device-%d", i), "password")
		if err != nil {
			t.Fatalf("open session %d: %v", i, err)
		}
		p.sessions = append(p.sessions, pair)
	}
	for i := 0; i < browsers; i++ {
		raw, err := f.svc.CreateLoginSession(ctx, p.userID, "198.51.100.7", fmt.Sprintf("browser-%d", i))
		if err != nil {
			t.Fatalf("open hosted-login session %d: %v", i, err)
		}
		p.browsers = append(p.browsers, raw)
	}
	for i := 0; i < grants; i++ {
		p.grants = append(p.grants, f.grantApp(t, ctx, p.userID))
	}
	return p
}

// grantApp signs the user in to the fixture's application, which then holds a
// refresh grant for them.
func (f *signOutEverywhereFixture) grantApp(t *testing.T, ctx context.Context, userID uuid.UUID) *oidc.TokenResponse {
	t.Helper()
	code, _, err := f.oidc.Authorize(ctx, userID, f.clientID, f.redirectURI, []string{"openid"}, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := f.oidc.ExchangeCode(ctx, f.clientID, f.secret, code, f.redirectURI, "", "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if issued.RefreshToken == "" {
		t.Fatal("the application received no refresh token")
	}
	return issued
}

type signOutEverywhereResponse struct {
	status    int
	code      string
	revoked   *int64
	sessions  *int64
	browsers  *int64
	grants    *int64
	setCookie []string
}

func (f *signOutEverywhereFixture) signOutEverywhere(t *testing.T, accessToken string) signOutEverywhereResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, signOutEverywherePath, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return decodeSignOutEverywhere(rr)
}

func decodeSignOutEverywhere(rr *httptest.ResponseRecorder) signOutEverywhereResponse {
	out := signOutEverywhereResponse{status: rr.Code, setCookie: rr.Result().Header.Values("Set-Cookie")}
	var body struct {
		Revoked  *int64 `json:"revoked"`
		Sessions *int64 `json:"sessions"`
		Browsers *int64 `json:"hosted_login_sessions"`
		Grants   *int64 `json:"app_grants"`
		Error    struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	out.revoked, out.sessions, out.browsers, out.grants = body.Revoked, body.Sessions, body.Browsers, body.Grants
	out.code = body.Error.Code
	if out.code == "" && rr.Code >= 400 {
		out.code = strings.TrimSpace(rr.Body.String())
	}
	return out
}

func wantCounts(t *testing.T, res signOutEverywhereResponse, total, sessions, browsers, grants int64) {
	t.Helper()
	got := func(v *int64) string {
		if v == nil {
			return "missing"
		}
		return fmt.Sprint(*v)
	}
	if res.revoked == nil || *res.revoked != total ||
		res.sessions == nil || *res.sessions != sessions ||
		res.browsers == nil || *res.browsers != browsers ||
		res.grants == nil || *res.grants != grants {
		t.Fatalf("counts = revoked %s (sessions %s, hosted %s, apps %s); want %d (%d, %d, %d)",
			got(res.revoked), got(res.sessions), got(res.browsers), got(res.grants), total, sessions, browsers, grants)
	}
}

// signedInAnywhere reports, per place, what still lets the person in: live API
// sessions, hosted-login sessions that still resolve, and grants whose refresh
// token can still be traded for new tokens. Trading rotates the grant, so only
// call it once per grant per test, or on grants expected to be dead.
func (f *signOutEverywhereFixture) stillSignedIn(t *testing.T, ctx context.Context, p *signIns) (sessions, browsers, grants int) {
	t.Helper()
	sessions = liveSessionCount(t, ctx, p.userID)
	for _, raw := range p.browsers {
		if _, err := f.svc.ResolveLoginSession(ctx, raw); err == nil {
			browsers++
		}
	}
	for _, g := range p.grants {
		if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, g.RefreshToken, ""); err == nil {
			grants++
		}
	}
	return sessions, browsers, grants
}

func clearsHostedLoginCookie(setCookies []string) bool {
	for _, c := range setCookies {
		if strings.HasPrefix(c, auth.LoginSessionCookie+"=;") || strings.HasPrefix(c, auth.LoginSessionCookie+"=\"\";") {
			if strings.Contains(c, "Max-Age=0") {
				return true
			}
		}
	}
	return false
}

// TestSignOutEverywhereEndsEverySignInIncludingTheCurrentOne covers: every API
// session ends including the caller's own; every hosted-login session ends and
// the caller's browser is told to drop the cookie; every application grant
// stops renewing; the response says how many ended (in total and per place,
// not counting what had already ended or expired); another person is not
// affected; the action is audited as a self-initiated global sign-out.
func TestSignOutEverywhereEndsEverySignInIncludingTheCurrentOne(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)

	me := f.newPerson(t, ctx, 4, 2, 2)
	current := me.sessions[0]
	// Already over before the action: one ended session, one expired hosted
	// sign-in, one rotated-away refresh token. None of them counts again.
	if err := f.svc.Logout(ctx, me.sessions[3].SessionID, me.userID); err != nil {
		t.Fatalf("pre-end a session: %v", err)
	}
	if _, err := testPool.Exec(ctx, `
		INSERT INTO auth.login_sessions (token_hash, user_id, expires_at)
		VALUES ($1, $2, NOW() - INTERVAL '1 minute')
	`, uniqueSlug("expired"), me.userID); err != nil {
		t.Fatalf("seed an expired hosted sign-in: %v", err)
	}
	rotated, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, me.grants[1].RefreshToken, "")
	if err != nil {
		t.Fatalf("rotate a grant: %v", err)
	}
	me.grants[1] = rotated

	someoneElse := f.newPerson(t, ctx, 2, 1, 1)

	res := f.signOutEverywhere(t, current.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("sign out everywhere status = %d (%s), want 200", res.status, res.code)
	}
	wantCounts(t, res, 7, 3, 2, 2)
	if !clearsHostedLoginCookie(res.setCookie) {
		t.Fatalf("the response must clear the hosted-login cookie, Set-Cookie = %q", res.setCookie)
	}

	if sessionIsLive(t, ctx, current.SessionID) {
		t.Fatal("the caller's own session must end too")
	}
	for _, pair := range me.sessions {
		if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
			t.Fatalf("refresh of session %s after signing out everywhere: err = %v, want session revoked", pair.SessionID, err)
		}
	}
	for i, g := range me.grants {
		if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, g.RefreshToken, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
			t.Fatalf("application grant %d still renews after signing out everywhere: err = %v", i, err)
		}
	}
	if s, b, g := f.stillSignedIn(t, ctx, me); s != 0 || b != 0 || g != 0 {
		t.Fatalf("still signed in after signing out everywhere: %d sessions, %d hosted, %d apps", s, b, g)
	}

	if s, b, g := f.stillSignedIn(t, ctx, someoneElse); s != 2 || b != 1 || g != 1 {
		t.Fatalf("another person was affected: %d sessions, %d hosted, %d apps still signed in; want 2, 1, 1", s, b, g)
	}

	var audits int
	var sessions, browsers, grants int64
	var subject string
	if err := testPool.QueryRow(ctx, `
		SELECT count(*),
		       COALESCE(max((metadata->>'revoked_sessions')::bigint), -1),
		       COALESCE(max((metadata->>'revoked_login_sessions')::bigint), -1),
		       COALESCE(max((metadata->>'revoked_app_grants')::bigint), -1),
		       COALESCE(max(metadata->>'session_id'), '')
		FROM audit.events
		WHERE actor_user_id = $1 AND resource_id = $1 AND action = 'auth.all_sessions_revoked'
	`, me.userID).Scan(&audits, &sessions, &browsers, &grants, &subject); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if audits != 1 || sessions != 3 || browsers != 2 || grants != 2 || subject != current.SessionID.String() {
		t.Fatalf("audit rows = %d (sessions %d, hosted %d, apps %d, session %q); want 1 (3, 2, 2, %s)",
			audits, sessions, browsers, grants, subject, current.SessionID)
	}
	var adminAudits int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = 'session.admin_revoked_all'
	`, me.userID).Scan(&adminAudits); err != nil {
		t.Fatalf("read admin audit: %v", err)
	}
	if adminAudits != 0 {
		t.Fatalf("a self-initiated sign-out was recorded as an administrative one (%d rows)", adminAudits)
	}
}

// TestSignOutEverywhereMakesTheNextAuthorizationAskToSignIn: a browser that is
// signed in to the hosted login goes straight back to the application before;
// after signing out everywhere (from another device) the same cookie no longer
// counts and the next authorization sends it to the sign-in page.
func TestSignOutEverywhereMakesTheNextAuthorizationAskToSignIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	me := f.newPerson(t, ctx, 1, 1, 0)
	if err := f.oidc.GrantConsent(ctx, me.userID, f.clientID, []string{"openid"}); err != nil {
		t.Fatalf("grant consent: %v", err)
	}

	authorize := func() string {
		t.Helper()
		q := url.Values{"client_id": {f.clientID}, "redirect_uri": {f.redirectURI}, "scope": {"openid"}, "state": {"s"}}
		req := httptest.NewRequest(http.MethodGet, "/v1/oauth/authorize?"+q.Encode(), nil)
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: me.browsers[0]})
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("authorize status = %d, want a redirect", rr.Code)
		}
		return rr.Header().Get("Location")
	}

	if loc := authorize(); !strings.HasPrefix(loc, f.redirectURI) || !strings.Contains(loc, "code=") {
		t.Fatalf("before: a signed-in browser should go straight back to the app, got %q", loc)
	}
	if res := f.signOutEverywhere(t, me.sessions[0].AccessToken); res.status != http.StatusOK {
		t.Fatalf("sign out everywhere status = %d (%s), want 200", res.status, res.code)
	}
	if loc := authorize(); !strings.HasPrefix(loc, "http://login.test/login") {
		t.Fatalf("after: the next authorization must ask the person to sign in, got %q", loc)
	}
}

// TestSignOutEverywhereRetriedSucceedsAndChangesNothing: running it again
// with the same (still unexpired) access token succeeds, reports zero, and
// touches nothing.
func TestSignOutEverywhereRetriedSucceedsAndChangesNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	me := f.newPerson(t, ctx, 2, 1, 1)
	current := me.sessions[0]

	first := f.signOutEverywhere(t, current.AccessToken)
	if first.status != http.StatusOK {
		t.Fatalf("first call status = %d (%s), want 200", first.status, first.code)
	}
	wantCounts(t, first, 4, 2, 1, 1)

	snapshot := func() string {
		t.Helper()
		var state string
		if err := testPool.QueryRow(ctx, `
			SELECT concat_ws('|',
				(SELECT string_agg(id::text || '@' || COALESCE(revoked_at::text, 'live'), ',' ORDER BY id)
				   FROM auth.sessions WHERE user_id = $1),
				(SELECT count(*)::text FROM auth.login_sessions WHERE user_id = $1),
				(SELECT string_agg(id::text || '@' || COALESCE(revoked_at::text, 'live'), ',' ORDER BY id)
				   FROM auth.oidc_refresh_tokens WHERE user_id = $1))
		`, me.userID).Scan(&state); err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		return state
	}
	before := snapshot()

	again := f.signOutEverywhere(t, current.AccessToken)
	if again.status != http.StatusOK {
		t.Fatalf("retry status = %d (%s), want 200", again.status, again.code)
	}
	wantCounts(t, again, 0, 0, 0, 0)
	if after := snapshot(); after != before {
		t.Fatalf("the retry changed state:\nbefore %s\nafter  %s", before, after)
	}
}

// TestSignOutEverywhereNeedsOneOfThePersonsOwnSessions: an access token that
// does not stand for one of the caller's own sessions — an application's
// token, or a token naming someone else's session — cannot sign anyone out.
func TestSignOutEverywhereNeedsOneOfThePersonsOwnSessions(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	me := f.newPerson(t, ctx, 2, 1, 1)
	someoneElse := f.newPerson(t, ctx, 1, 0, 0)

	appToken := me.grants[0].AccessToken
	borrowed, _, err := f.issuer.IssueAccess(me.userID, uuid.Nil, someoneElse.sessions[0].SessionID, "")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	for name, token := range map[string]string{"application token": appToken, "someone else's session": borrowed} {
		res := f.signOutEverywhere(t, token)
		if res.status != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d (%s), want 401", name, res.status, res.code)
		}
	}
	if got := liveSessionCount(t, ctx, me.userID); got != 2 {
		t.Fatalf("live sessions = %d, want the 2 untouched", got)
	}
	if got := liveSessionCount(t, ctx, someoneElse.userID); got != 1 {
		t.Fatalf("the other person's live sessions = %d, want 1", got)
	}
	if _, err := f.svc.ResolveLoginSession(ctx, me.browsers[0]); err != nil {
		t.Fatalf("hosted sign-in must be untouched: %v", err)
	}
}

// TestSignOutEverywhereReportsFailureAndEndsNothing: if any part cannot be
// ended (here: an application grant) the call fails and nothing is left
// ended — the sessions, the hosted sign-in and the grants all still work.
func TestSignOutEverywhereReportsFailureAndEndsNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	me := f.newPerson(t, ctx, 2, 1, 1)

	name := "test_block_grant_end_" + strings.ReplaceAll(me.userID.String(), "-", "")
	if _, err := testPool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION %[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION 'forced failure ending an application grant';
		END $$;
		CREATE TRIGGER %[1]s BEFORE UPDATE ON auth.oidc_refresh_tokens
		FOR EACH ROW WHEN (OLD.user_id = '%[2]s'::uuid AND NEW.revoked_at IS NOT NULL) EXECUTE FUNCTION %[1]s();
	`, name, me.userID)); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}
	dropTrigger := func() {
		_, _ = testPool.Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %[1]s ON auth.oidc_refresh_tokens; DROP FUNCTION IF EXISTS %[1]s()", name))
	}
	t.Cleanup(dropTrigger)

	res := f.signOutEverywhere(t, me.sessions[0].AccessToken)
	if res.status < 500 {
		t.Fatalf("status = %d (%s), want a server error when a grant cannot be ended", res.status, res.code)
	}
	if res.revoked != nil {
		t.Fatalf("a failed call must not report a count, got %d", *res.revoked)
	}
	dropTrigger()
	if s, b, g := f.stillSignedIn(t, ctx, me); s != 2 || b != 1 || g != 1 {
		t.Fatalf("after a failed call: %d sessions, %d hosted, %d apps still signed in; want all (2, 1, 1)", s, b, g)
	}
	var audits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.all_sessions_revoked'`, me.userID).Scan(&audits); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if audits != 0 {
		t.Fatalf("a failed call left %d audit rows", audits)
	}
}

// TestSignOutEverywhereAlsoEndsAGrantRenewedWhileItRuns: an application was
// in the middle of renewing its grant when the person signed out everywhere.
// The renewal commits a successor token after the sign-out has already looked
// at the grant; that successor must not survive.
func TestSignOutEverywhereAlsoEndsAGrantRenewedWhileItRuns(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	me := f.newPerson(t, ctx, 1, 0, 1)
	presented := tokens.HashRefresh(me.grants[0].RefreshToken)

	// The renewal, held open mid-way exactly as the refresh grant runs it: the
	// presented token is locked, its successor written, the presented one
	// marked used — not yet committed.
	renewal, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin renewal: %v", err)
	}
	defer renewal.Rollback(ctx)
	successorRaw, successorHash, err := tokens.NewRefreshToken()
	if err != nil {
		t.Fatalf("new refresh token: %v", err)
	}
	var presentedID, successorID uuid.UUID
	if err := renewal.QueryRow(ctx, `SELECT id FROM auth.oidc_refresh_tokens WHERE token_hash = $1 FOR UPDATE`, presented).Scan(&presentedID); err != nil {
		t.Fatalf("lock presented token: %v", err)
	}
	if err := renewal.QueryRow(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, scopes, expires_at)
		SELECT $1, client_id, user_id, tenant_id, scopes, NOW() + INTERVAL '30 days'
		FROM auth.oidc_refresh_tokens WHERE id = $2
		RETURNING id
	`, successorHash, presentedID).Scan(&successorID); err != nil {
		t.Fatalf("write successor: %v", err)
	}
	if _, err := renewal.Exec(ctx, `UPDATE auth.oidc_refresh_tokens SET used_at = NOW(), replaced_by = $1 WHERE id = $2`, successorID, presentedID); err != nil {
		t.Fatalf("mark presented used: %v", err)
	}

	done := make(chan signOutEverywhereResponse, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, signOutEverywherePath, nil)
		req.Header.Set("Authorization", "Bearer "+me.sessions[0].AccessToken)
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		done <- decodeSignOutEverywhere(rr)
	}()

	// Let the sign-out reach the grant and wait on the renewal's lock (or
	// finish, if it never touches the grant), then let the renewal commit.
	deadline := time.Now().Add(10 * time.Second)
	var res *signOutEverywhereResponse
	for res == nil {
		var waiting bool
		if err := testPool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			               WHERE wait_event_type = 'Lock' AND query ILIKE '%oidc_refresh_tokens%')
		`).Scan(&waiting); err != nil {
			t.Fatalf("watch locks: %v", err)
		}
		if waiting {
			break
		}
		select {
		case r := <-done:
			res = &r
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("sign out everywhere neither finished nor reached the grant")
		}
	}
	if err := renewal.Commit(ctx); err != nil {
		t.Fatalf("commit renewal: %v", err)
	}
	if res == nil {
		select {
		case r := <-done:
			res = &r
		case <-time.After(10 * time.Second):
			t.Fatal("sign out everywhere did not finish after the renewal committed")
		}
	}
	if res.status != http.StatusOK {
		t.Fatalf("sign out everywhere status = %d (%s), want 200", res.status, res.code)
	}
	if _, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, successorRaw, ""); !errors.Is(err, errs.ErrOIDCRefreshTokenRevoked) {
		t.Fatalf("the token renewed during the sign-out still works: err = %v", err)
	}
	if res.grants == nil || *res.grants != 1 {
		t.Fatalf("app grants ended = %v, want the one grant counted once", res.grants)
	}
}

// TestAdminForceSignOutEndsEverySignInOfThePerson: an administrator's force
// sign-out ends the person's API sessions, hosted-login sessions and
// application grants in one step, reports how many, leaves everyone else alone,
// and is recorded as an administrative force sign-out.
func TestAdminForceSignOutEndsEverySignInOfThePerson(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newSignOutEverywhereFixture(t, ctx)
	target := f.newPerson(t, ctx, 2, 1, 1)
	bystander := f.newPerson(t, ctx, 1, 1, 1)
	adminID := createUserInTenant(t, ctx, f.tenantID)

	handler := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: f.svc}
	router := chi.NewRouter()
	router.Use(chimiddleware.RequestID)
	router.Use(withPrincipal(adminID, f.tenantID))
	handler.Mount(router)

	req := httptest.NewRequest(http.MethodPost, "/users/"+target.userID.String()+"/sessions/revoke-all", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	res := decodeSignOutEverywhere(rr)
	if res.status != http.StatusOK {
		t.Fatalf("force sign-out status = %d (%s), want 200", res.status, res.code)
	}
	if s, b, g := f.stillSignedIn(t, ctx, target); s != 0 || b != 0 || g != 0 {
		t.Fatalf("still signed in after a force sign-out: %d sessions, %d hosted, %d apps", s, b, g)
	}
	wantCounts(t, res, 4, 2, 1, 1)
	if s, b, g := f.stillSignedIn(t, ctx, bystander); s != 1 || b != 1 || g != 1 {
		t.Fatalf("a bystander was affected: %d sessions, %d hosted, %d apps; want 1, 1, 1", s, b, g)
	}

	var audits int
	var actor uuid.UUID
	var sessions, browsers, grants int64
	if err := testPool.QueryRow(ctx, `
		SELECT count(*), COALESCE(max(actor_user_id::text), '00000000-0000-0000-0000-000000000000')::uuid,
		       COALESCE(max((metadata->>'revoked_sessions')::bigint), -1),
		       COALESCE(max((metadata->>'revoked_login_sessions')::bigint), -1),
		       COALESCE(max((metadata->>'revoked_app_grants')::bigint), -1)
		FROM audit.events WHERE resource_id = $1 AND action = 'session.admin_revoked_all'
	`, target.userID).Scan(&audits, &actor, &sessions, &browsers, &grants); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if audits != 1 || actor != adminID || sessions != 2 || browsers != 1 || grants != 1 {
		t.Fatalf("audit rows = %d by %s (sessions %d, hosted %d, apps %d); want 1 by %s (2, 1, 1)",
			audits, actor, sessions, browsers, grants, adminID)
	}
	var selfAudits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = 'auth.all_sessions_revoked'`, target.userID).Scan(&selfAudits); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if selfAudits != 0 {
		t.Fatalf("an administrative force sign-out was recorded as self-initiated (%d rows)", selfAudits)
	}
}
