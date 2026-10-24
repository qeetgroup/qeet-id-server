//go:build integration

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// live reports whether session is one of userID's live sessions, failing t
// when that can't be read.
func live(t *testing.T, svc *Service, session, userID uuid.UUID) bool {
	t.Helper()
	ok, err := svc.SessionLive(dbtest.Context(t), session, userID)
	if err != nil {
		t.Fatalf("session live: %v", err)
	}
	return ok
}

// TestRefreshOverHTTP checks renewal through the API: it rotates the refresh
// token for the same session, an unknown token is refused, and presenting the
// spent token ends the session, so its replacement is refused too.
func TestRefreshOverHTTP(t *testing.T) {
	svc := newService(t)
	b := newBrowser(t, publicRoutes(newHandler(svc)))
	a, _ := member(t)
	first := signIn(t, svc, a)
	refresh := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		return b.do(http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": token})
	}

	rec := refresh(first.RefreshToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	var second TokenPair
	dbtest.Decode(t, rec, &second)
	if second.SessionID != first.SessionID || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken || second.AccessToken == "" {
		t.Fatalf("refresh returned %+v; want a new pair for session %s", second, first.SessionID)
	}
	for _, tc := range []struct {
		name, token string
		status      int
		code        string
	}{
		{"no token", "", http.StatusUnprocessableEntity, errs.CodeValidation},
		{"an unknown token", dbtest.Unique("token"), http.StatusUnauthorized, errs.CodeAuthRefreshTokenInvalid},
		{"the spent token", first.RefreshToken, http.StatusUnauthorized, errs.CodeAuthSessionRevoked},
		{"its replacement", second.RefreshToken, http.StatusUnauthorized, errs.CodeAuthSessionRevoked},
	} {
		if rec := refresh(tc.token); !answered(rec, tc.status, tc.code) {
			t.Errorf("refresh with %s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1
		AND host(ip) = $2`, first.SessionID, b.ip); n != 1 {
		t.Errorf("the reuse was audited %d times with the client's address, want 1", n)
	}
}

// TestRefreshRefusedOnceInactive checks that a session stops renewing once its
// account is suspended or deleted, or its organisation suspended, though
// neither ended it, and that an expired refresh token is refused.
func TestRefreshRefusedOnceInactive(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	for _, tc := range []struct {
		name, change string
		want         error
	}{
		{"suspended account", `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, errs.ErrAuthAccountSuspended},
		{"deleted account", `UPDATE "user".users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, errs.ErrAuthAccountSuspended},
		{"suspended organisation", `UPDATE tenant.tenants SET status = 'suspended' WHERE id = (SELECT tenant_id FROM "user".users WHERE id = $1)`, errs.ErrAuthTenantInactive},
		{"expired refresh token", `UPDATE auth.refresh_tokens SET expires_at = NOW() - INTERVAL '1 second'
			WHERE session_id IN (SELECT id FROM auth.sessions WHERE user_id = $1)`, errs.ErrAuthRefreshTokenInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := member(t)
			pair := signIn(t, svc, a)
			if _, err := dbtest.Pool(t).Exec(ctx, tc.change, a.ID); err != nil {
				t.Fatal(err)
			}
			if res, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, tc.want) || res != nil {
				t.Errorf("refresh: %+v, %v; want %v", res, err, tc.want)
			}
		})
	}
}

// TestSessionTimeouts checks that a session idle past its timeout, or past its
// maximum age, no longer renews; that the first renewal to notice records the
// ending once, with the bound it reached; and that the session then lists as
// expired and is no longer live for its access tokens.
func TestSessionTimeouts(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	for _, tc := range []struct{ reason, change string }{
		{timedOutIdle, `UPDATE auth.sessions SET last_seen_at = NOW() - INTERVAL '25 hours' WHERE id = $1`},
		{timedOutMaxAge, `UPDATE auth.sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			a, _ := member(t)
			pair := signIn(t, svc, a)
			if _, err := dbtest.Pool(t).Exec(ctx, tc.change, pair.SessionID); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionTimedOut) {
					t.Fatalf("renewal %d: %v, want %v", i+1, err, errs.ErrAuthSessionTimedOut)
				}
			}
			if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.session_expired' AND resource_id = $1
				AND metadata->>'reason' = $2`, pair.SessionID, tc.reason); n != 1 {
				t.Errorf("the ending was recorded %d times, want once", n)
			}
			if live(t, svc, pair.SessionID, a.ID) {
				t.Error("the timed-out session is still live")
			}
			sessions, err := svc.ListSessions(ctx, a.ID)
			if err != nil || len(sessions) != 1 || sessions[0].Status != "expired" {
				t.Errorf("sessions %+v, %v; want the one, expired", sessions, err)
			}
		})
	}
}

// sessionPage is a page of GET /auth/sessions.
type sessionPage struct {
	Items []struct {
		ID      uuid.UUID `json:"id"`
		Current bool      `json:"current"`
		Status  string    `json:"status"`
	} `json:"items"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
	Total      int    `json:"total"`
}

// TestSessionsOverHTTP checks a person's own sessions through the API: the
// list pages newest first, marks the calling session and refuses a cursor
// that isn't theirs; ending one of theirs works while naming someone else's
// ends nothing; ending the others keeps the calling one; and signing out ends
// that too, after which it can end nothing more.
func TestSessionsOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, tenant := member(t)
	stranger, _ := member(t)
	oldest, older := signIn(t, svc, a), signIn(t, svc, a)
	current := signIn(t, svc, a)
	theirs := signIn(t, svc, stranger)
	p := dbtest.Principal(a.ID, tenant)
	p.SessionID = &current.SessionID
	h := dbtest.Serve(p, newHandler(svc).MountAuthed)
	call := func(method, path string, status int, code string) *httptest.ResponseRecorder {
		t.Helper()
		rec := dbtest.Do(t, h, method, path, nil)
		if !answered(rec, status, code) {
			t.Fatalf("%s %s: %d %s, want %d %s", method, path, rec.Code, rec.Body.String(), status, code)
		}
		return rec
	}

	var me struct {
		UserID    uuid.UUID `json:"user_id"`
		TenantID  uuid.UUID `json:"tenant_id"`
		SessionID uuid.UUID `json:"session_id"`
	}
	dbtest.Decode(t, call(http.MethodGet, "/auth/me", http.StatusOK, ""), &me)
	if me.UserID != a.ID || me.TenantID != tenant || me.SessionID != current.SessionID {
		t.Errorf("me %+v, want %s in %s on %s", me, a.ID, tenant, current.SessionID)
	}

	var first, second sessionPage
	dbtest.Decode(t, call(http.MethodGet, "/auth/sessions?limit=2", http.StatusOK, ""), &first)
	if len(first.Items) != 2 || first.Items[0].ID != current.SessionID || !first.Items[0].Current ||
		first.Items[1].ID != older.SessionID || first.Items[1].Current || !first.HasMore || first.Total != 3 {
		t.Fatalf("first page %+v; want the current then the older session, of 3", first)
	}
	dbtest.Decode(t, call(http.MethodGet, "/auth/sessions?limit=2&cursor="+first.NextCursor, http.StatusOK, ""), &second)
	if len(second.Items) != 1 || second.Items[0].ID != oldest.SessionID || second.HasMore {
		t.Errorf("second page %+v; want the oldest session alone", second)
	}
	call(http.MethodGet, "/auth/sessions?cursor="+theirs.SessionID.String(), http.StatusBadRequest, errs.CodeBadRequest)
	call(http.MethodGet, "/auth/sessions?cursor=not-a-session", http.StatusBadRequest, errs.CodeBadRequest)

	call(http.MethodDelete, "/auth/sessions/"+theirs.SessionID.String(), http.StatusOK, "")
	if !live(t, svc, theirs.SessionID, stranger.ID) {
		t.Error("naming someone else's session ended it")
	}
	call(http.MethodDelete, "/auth/sessions/"+oldest.SessionID.String(), http.StatusOK, "")
	call(http.MethodDelete, "/auth/sessions/not-a-session", http.StatusBadRequest, errs.CodeBadRequest)
	var revoked struct {
		Revoked int `json:"revoked"`
	}
	dbtest.Decode(t, call(http.MethodPost, "/auth/sessions/revoke-others", http.StatusOK, ""), &revoked)
	if revoked.Revoked != 1 {
		t.Errorf("ending the other sessions ended %d, want the one still live", revoked.Revoked)
	}
	for _, tc := range []struct {
		name    string
		session uuid.UUID
		want    bool
	}{{"the oldest session", oldest.SessionID, false}, {"the older session", older.SessionID, false}, {"the current session", current.SessionID, true}} {
		if got := live(t, svc, tc.session, a.ID); got != tc.want {
			t.Errorf("%s live %v, want %v", tc.name, got, tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.other_sessions_revoked' AND resource_id = $1
		AND (metadata->>'revoked_sessions')::int = 1`, a.ID); n != 1 {
		t.Errorf("ending the other sessions was audited %d times, want 1", n)
	}

	call(http.MethodPost, "/auth/logout", http.StatusOK, "")
	if live(t, svc, current.SessionID, a.ID) {
		t.Error("signing out left the session live")
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: current.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Errorf("refresh after signing out: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
	call(http.MethodPost, "/auth/sessions/revoke-others", http.StatusUnauthorized, errs.CodeAuthSessionRevoked)
}

// signedInEverywhere gives a two sessions, a hosted-login session, a
// remembered device and an application grant in tenant, and returns the
// first session.
func signedInEverywhere(t *testing.T, svc *Service, a dbtest.Account, tenant uuid.UUID) *TokenPair {
	t.Helper()
	ctx := dbtest.Context(t)
	pair := signIn(t, svc, a)
	signIn(t, svc, a)
	if _, err := svc.CreateLoginSession(ctx, a.ID, "", testUserAgent); err != nil {
		t.Fatalf("hosted-login session: %v", err)
	}
	if _, err := svc.CreateTrustedDevice(ctx, a.ID, tenant, testUserAgent, time.Hour); err != nil {
		t.Fatalf("remembered device: %v", err)
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `
		INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at)
		VALUES ($1, 'app', $2, $3, NOW() + INTERVAL '1 day')
	`, dbtest.Unique("grant"), a.ID, tenant); err != nil {
		t.Fatalf("application grant: %v", err)
	}
	return pair
}

// signedInWays counts a's live sessions, hosted-login sessions, remembered
// devices and live application grants.
func signedInWays(t *testing.T, a dbtest.Account) [4]int {
	t.Helper()
	return [4]int{
		dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND revoked_at IS NULL`, a.ID),
		dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID),
		dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID),
		dbtest.Count(t, `SELECT count(*) FROM auth.oidc_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, a.ID),
	}
}

// TestSignOutEverywhere checks that signing out everywhere ends every way the
// caller is signed in — sessions, the calling one included, hosted-login
// sessions, remembered devices and application grants — clears the hosted
// login's cookie, leaves another person's untouched, answers zeros when
// repeated, and refuses a session that isn't the caller's.
func TestSignOutEverywhere(t *testing.T) {
	svc := newService(t)
	a, tenant := member(t)
	stranger, strangers := member(t)
	current := signedInEverywhere(t, svc, a, tenant)
	theirs := signedInEverywhere(t, svc, stranger, strangers)
	p := dbtest.Principal(a.ID, tenant)
	p.SessionID = &current.SessionID
	b := newBrowser(t, dbtest.Serve(p, newHandler(svc).MountAuthed))
	type ended struct {
		Revoked        int `json:"revoked"`
		Sessions       int `json:"sessions"`
		LoginSessions  int `json:"hosted_login_sessions"`
		AppGrants      int `json:"app_grants"`
		TrustedDevices int `json:"trusted_devices"`
	}

	rec := b.do(http.MethodPost, "/auth/sessions/revoke-all", nil)
	var got ended
	dbtest.Decode(t, rec, &got)
	if want := (ended{Revoked: 4, Sessions: 2, LoginSessions: 1, AppGrants: 1, TrustedDevices: 1}); rec.Code != http.StatusOK || got != want {
		t.Fatalf("sign out everywhere: %d %+v, want 200 %+v", rec.Code, got, want)
	}
	if c := setCookie(rec, LoginSessionCookie); c == nil || c.MaxAge >= 0 || !c.HttpOnly || !c.Secure {
		t.Errorf("hosted-login cookie %+v, want it cleared, HttpOnly and Secure", c)
	}
	if ways := signedInWays(t, a); ways != [4]int{} {
		t.Errorf("signed in after signing out everywhere: %v sessions, hosted sessions, devices, grants", ways)
	}
	if ways := signedInWays(t, stranger); ways != [4]int{2, 1, 1, 1} {
		t.Errorf("another person's ways in %v, want them untouched", ways)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.all_sessions_revoked' AND resource_id = $1
		AND (metadata->>'revoked_sessions')::int = 2`, a.ID); n != 1 {
		t.Errorf("signing out everywhere was audited %d times, want 1", n)
	}

	rec = b.do(http.MethodPost, "/auth/sessions/revoke-all", nil)
	got = ended{}
	dbtest.Decode(t, rec, &got)
	if rec.Code != http.StatusOK || got != (ended{}) {
		t.Errorf("sign out everywhere again: %d %+v, want 200 and zeros", rec.Code, got)
	}
	p.SessionID = &theirs.SessionID
	if rec := b.do(http.MethodPost, "/auth/sessions/revoke-all", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("sign out everywhere naming someone else's session: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if ways := signedInWays(t, stranger); ways != [4]int{2, 1, 1, 1} {
		t.Errorf("naming someone else's session ended their ways in: %v", ways)
	}
}

// TestSessionLimitEvictsLeastRecentlyUsed checks that at the organisation's
// session limit a new sign-in ends the least recently used session, not the
// oldest, records why, and counts only sessions in that organisation.
func TestSessionLimitEvictsLeastRecentlyUsed(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	a, tenant := member(t)
	other := dbtest.Tenant(t)
	dbtest.Assign(t, a.ID, other, dbtest.Role(t, other))
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.security_policies (tenant_id, max_sessions) VALUES ($1, 2)`, tenant); err != nil {
		t.Fatal(err)
	}
	oldest, idle := signIn(t, svc, a), signIn(t, svc, a)
	elsewhere, err := svc.IssuePair(ctx, a.ID, other, "", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE auth.sessions SET last_seen_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, idle.SessionID); err != nil {
		t.Fatal(err)
	}

	newest := signIn(t, svc, a)
	for _, tc := range []struct {
		name    string
		session uuid.UUID
		want    bool
	}{
		{"the oldest, recently used session", oldest.SessionID, true},
		{"the least recently used session", idle.SessionID, false},
		{"the new session", newest.SessionID, true},
		{"the session in another organisation", elsewhere.SessionID, true},
	} {
		if got := live(t, svc, tc.session, a.ID); got != tc.want {
			t.Errorf("%s live %v, want %v", tc.name, got, tc.want)
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.session_evicted' AND resource_id = $1
		AND metadata->>'reason' = 'session_limit'`, idle.SessionID); n != 1 {
		t.Errorf("the eviction was recorded %d times, want 1", n)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: idle.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Errorf("refresh the evicted session: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
}

// TestSessionUse checks that a request made with a session's access token
// moves its last use, so its idle timeout counts from then, and never
// revives a session that has ended.
func TestSessionUse(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	a, _ := member(t)
	used, revoked, idle := signIn(t, svc, a), signIn(t, svc, a), signIn(t, svc, a)
	if _, err := pool.Exec(ctx, `
		UPDATE auth.sessions SET last_seen_at = NOW() - CASE WHEN id = $3 THEN INTERVAL '25 hours' ELSE INTERVAL '2 hours' END,
		       revoked_at = CASE WHEN id = $2 THEN NOW() END
		WHERE id = ANY($1)
	`, []uuid.UUID{used.SessionID, revoked.SessionID, idle.SessionID}, revoked.SessionID, idle.SessionID); err != nil {
		t.Fatal(err)
	}

	for _, pair := range []*TokenPair{used, revoked, idle} {
		svc.SessionUsed(ctx, pair.SessionID)
	}
	recent := func(session uuid.UUID) bool {
		return dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND last_seen_at > NOW() - INTERVAL '1 minute'`, session) == 1
	}
	if !recent(used.SessionID) || !live(t, svc, used.SessionID, a.ID) {
		t.Error("a used session's last use did not move")
	}
	if recent(revoked.SessionID) || recent(idle.SessionID) || live(t, svc, idle.SessionID, a.ID) {
		t.Error("using an ended session revived it")
	}
}

// TestPurgeEndedSessions checks that the cleanup deletes sessions ended or
// expired longer ago than the retention, with their refresh tokens, and
// hosted-login sessions and remembered devices expired as long ago, keeping
// live ones and those ended recently.
func TestPurgeEndedSessions(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	a, tenant := member(t)
	kept, endedLongAgo, endedRecently, expiredLongAgo := signIn(t, svc, a), signIn(t, svc, a), signIn(t, svc, a), signIn(t, svc, a)
	if _, err := pool.Exec(ctx, `
		UPDATE auth.sessions SET
		    created_at = NOW() - CASE WHEN id = $3 THEN INTERVAL '40 days' ELSE INTERVAL '10 days' END,
		    revoked_at = CASE WHEN id = $1 THEN NOW() - INTERVAL '8 days' WHEN id = $2 THEN NOW() - INTERVAL '1 day' END,
		    last_seen_at = NOW() - CASE WHEN id = $3 THEN INTERVAL '39 days' ELSE INTERVAL '1 day' END,
		    expires_at = CASE WHEN id = $3 THEN NOW() - INTERVAL '9 days' ELSE expires_at END
		WHERE id IN ($1, $2, $3)
	`, endedLongAgo.SessionID, endedRecently.SessionID, expiredLongAgo.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		WITH logins AS (
			INSERT INTO auth.login_sessions (token_hash, user_id, expires_at)
			VALUES ($2, $1, NOW() - INTERVAL '8 days'), ($3, $1, NOW() + INTERVAL '1 hour')
		)
		INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $4, $2, NOW() - INTERVAL '8 days'), ($1, $4, $3, NOW() + INTERVAL '1 day')
	`, a.ID, dbtest.Unique("old"), dbtest.Unique("live"), tenant); err != nil {
		t.Fatal(err)
	}

	purged, err := PurgeEndedSessions(ctx, pool, SessionRetention, nil)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged.Sessions < 2 || purged.LoginSessions < 1 || purged.TrustedDevices < 1 {
		t.Errorf("purged %+v, want at least 2 sessions, 1 hosted-login session and 1 device", purged)
	}
	rows, err := pool.Query(ctx, `SELECT id FROM auth.sessions WHERE user_id = $1`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var left []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if rows.Err() != nil || len(left) != 2 || !slices.Contains(left, kept.SessionID) || !slices.Contains(left, endedRecently.SessionID) {
		t.Errorf("sessions left %v, want the live one and the one ended recently", left)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.refresh_tokens WHERE session_id = ANY($1)`,
		[]uuid.UUID{endedLongAgo.SessionID, expiredLongAgo.SessionID}); n != 0 {
		t.Errorf("%d refresh tokens of purged sessions survived", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID) +
		dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 2 {
		t.Errorf("%d hosted-login sessions and devices left, want the live one of each", n)
	}
}

// TestPasswordOverHTTP checks the self-service password routes: the status
// and sign-in methods report a password; a change needs the current one,
// keeps the calling session and ends the others, after which only the new
// password is right; and an account without a password sets one with none.
func TestPasswordOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetRegistrationPolicy(anyPassword{})
	const next = "Nx8!rTq4-Lw2mZ"
	serve := func(a dbtest.Account, tenant uuid.UUID, session *TokenPair) http.Handler {
		p := dbtest.Principal(a.ID, tenant)
		p.SessionID = &session.SessionID
		return dbtest.Serve(p, newHandler(svc).MountAuthed)
	}
	hasPassword := func(h http.Handler) bool {
		t.Helper()
		var got struct {
			HasPassword bool `json:"has_password"`
		}
		dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/auth/password", nil), &got)
		return got.HasPassword
	}
	reauth := func(a dbtest.Account, plain string) (bool, bool) {
		t.Helper()
		has, ok, err := svc.ReauthPassword(ctx, a.ID, plain)
		if err != nil {
			t.Fatal(err)
		}
		return has, ok
	}

	a, tenant := member(t)
	current, other := signIn(t, svc, a), signIn(t, svc, a)
	h := serve(a, tenant, current)
	if !hasPassword(h) {
		t.Error("password status: none, want one")
	}
	var methods struct {
		Password bool `json:"password"`
		Total    int  `json:"total"`
	}
	dbtest.Decode(t, dbtest.Do(t, h, http.MethodGet, "/auth/sign-in-methods", nil), &methods)
	if !methods.Password || methods.Total != 1 {
		t.Errorf("sign-in methods %+v, want the password alone", methods)
	}
	for _, tc := range []struct {
		name   string
		body   map[string]string
		status int
		code   string
	}{
		{"without a new password", map[string]string{"current_password": testPassword}, http.StatusUnprocessableEntity, errs.CodeValidation},
		{"with the wrong current password", map[string]string{"current_password": "Wrong-password-1", "new_password": next}, http.StatusUnauthorized, errs.CodeAuthInvalidCredentials},
		{"without the current password", map[string]string{"new_password": next}, http.StatusUnauthorized, errs.CodeAuthInvalidCredentials},
	} {
		if rec := dbtest.Do(t, h, http.MethodPost, "/auth/password", tc.body); !answered(rec, tc.status, tc.code) {
			t.Errorf("change the password %s: %d %s, want %d %s", tc.name, rec.Code, rec.Body.String(), tc.status, tc.code)
		}
	}
	if _, ok := reauth(a, testPassword); !ok || !live(t, svc, other.SessionID, a.ID) {
		t.Fatal("a refused change altered the password or ended a session")
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/auth/password", map[string]string{"current_password": testPassword, "new_password": next}); rec.Code != http.StatusOK {
		t.Fatalf("change the password: %d %s", rec.Code, rec.Body.String())
	}
	if !live(t, svc, current.SessionID, a.ID) || live(t, svc, other.SessionID, a.ID) {
		t.Error("the change did not keep the calling session alone")
	}
	if _, ok := reauth(a, next); !ok {
		t.Error("the new password is not right")
	}
	if _, ok := reauth(a, testPassword); ok {
		t.Error("the old password is still right")
	}

	passwordless := dbtest.User(t, tenant, tenant)
	pair, err := svc.IssuePair(ctx, passwordless.ID, tenant, "", "test", "passkey")
	if err != nil {
		t.Fatal(err)
	}
	h = serve(passwordless, tenant, pair)
	if has, _ := reauth(passwordless, ""); has || hasPassword(h) {
		t.Fatal("an account without a password reports one")
	}
	if rec := dbtest.Do(t, h, http.MethodPost, "/auth/password", map[string]string{"new_password": next}); rec.Code != http.StatusOK {
		t.Fatalf("set a first password: %d %s", rec.Code, rec.Body.String())
	}
	if !hasPassword(h) {
		t.Error("password status after setting one: none")
	}
}

// TestSwitchStaysWithinMemberships checks that a switch enters only an active
// organisation the person belongs to, from a live session of their own, and
// replaces that session with one ending no later, after which the old one
// neither renews, lists nor switches again.
func TestSwitchStaysWithinMemberships(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, home := member(t)
	stranger, _ := member(t)
	joined, suspended := dbtest.Tenant(t), dbtest.Tenant(t)
	for _, tenant := range []uuid.UUID{joined, suspended} {
		dbtest.Assign(t, a.ID, tenant, dbtest.Role(t, tenant))
	}
	if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, suspended); err != nil {
		t.Fatal(err)
	}
	pair, theirs := signIn(t, svc, a), signIn(t, svc, stranger)
	switchTo := func(from *TokenPair, tenant uuid.UUID) (*TokenPair, error) {
		return svc.SwitchTenant(ctx, SwitchTenantInput{UserID: a.ID, FromSessionID: from.SessionID, TenantID: tenant})
	}

	for _, tc := range []struct {
		name   string
		from   *TokenPair
		tenant uuid.UUID
		want   error
	}{
		{"an organisation they don't belong to", pair, dbtest.Tenant(t), errs.ErrAuthNotTenantMember},
		{"a suspended organisation", pair, suspended, errs.ErrAuthNotTenantMember},
		{"from someone else's session", theirs, joined, errs.ErrUnauthorized},
	} {
		if next, err := switchTo(tc.from, tc.tenant); !errors.Is(err, tc.want) || next != nil {
			t.Errorf("switch into %s: %+v, %v; want %v", tc.name, next, err, tc.want)
		}
	}
	if !live(t, svc, pair.SessionID, a.ID) || !live(t, svc, theirs.SessionID, stranger.ID) {
		t.Fatal("a refused switch ended a session")
	}

	next, err := switchTo(pair, joined)
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if next.TenantID == nil || *next.TenantID != joined || next.SessionExpiresAt.After(pair.SessionExpiresAt) {
		t.Errorf("switched into %v ending %s, want %s ending no later than %s", next.TenantID, next.SessionExpiresAt, joined, pair.SessionExpiresAt)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Errorf("refresh the session switched from: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
	sessions, err := svc.ListSessions(ctx, a.ID)
	if err != nil || len(sessions) != 1 || sessions[0].ID != next.SessionID {
		t.Errorf("sessions %+v, %v; want only the one switched into", sessions, err)
	}
	if again, err := switchTo(pair, home); !errors.Is(err, errs.ErrUnauthorized) || again != nil {
		t.Errorf("switch again from the replaced session: %+v, %v; want %v", again, err, errs.ErrUnauthorized)
	}
}
