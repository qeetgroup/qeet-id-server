//go:build integration

package authentication

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPasswordSignInOverHTTP checks that the right password, whatever the
// case of the address, answers a token pair for a live session recorded with
// the client's address and browser, and that a body missing the password is
// refused before any account is looked at.
func TestPasswordSignInOverHTTP(t *testing.T) {
	svc := newService(t)
	b := newBrowser(t, publicRoutes(newHandler(svc)))
	a, organization := member(t)

	for _, email := range []string{a.Email, strings.ToUpper(a.Email)} {
		rec := b.do(http.MethodPost, "/auth/login", loginBody(email, testPassword))
		if rec.Code != http.StatusOK {
			t.Fatalf("sign in as %s: %d %s, want 200", email, rec.Code, rec.Body.String())
		}
		var pair TokenPair
		dbtest.Decode(t, rec, &pair)
		if pair.UserID != a.ID || pair.OrganizationID == nil || *pair.OrganizationID != organization || pair.RefreshToken == "" || pair.TokenType != "Bearer" {
			t.Fatalf("token pair %+v; want a Bearer pair for %s in %s", pair, a.ID, organization)
		}
		if claims, err := svc.tokens.VerifyAccess(pair.AccessToken); err != nil || claims.SessionID != pair.SessionID {
			t.Errorf("access token claims %+v, %v; want session %s", claims, err, pair.SessionID)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE id = $1 AND user_id = $2 AND host(ip) = $3
			AND user_agent = $4 AND revoked_at IS NULL`, pair.SessionID, a.ID, b.ip, testUserAgent); n != 1 {
			t.Errorf("no live session recorded with the client's address and browser")
		}
	}
	if rec := b.do(http.MethodPost, "/auth/login", map[string]string{"email": a.Email}); !answered(rec, http.StatusUnprocessableEntity, errs.CodeValidation) {
		t.Errorf("sign in without a password: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
	if rec := b.do(http.MethodPost, "/auth/login", loginBody("not-an-address", testPassword)); !answered(rec, http.StatusUnprocessableEntity, errs.CodeValidation) {
		t.Errorf("sign in with a malformed address: %d %s, want 422 %s", rec.Code, rec.Body.String(), errs.CodeValidation)
	}
}

// TestSignInAnswersAlikeOverHTTP checks that a wrong password, an address with
// no account, a deleted account and a wrong password for a suspended account
// all get the very same answer, that only the right password learns an
// account is suspended, and that no record keeps what was submitted.
func TestSignInAnswersAlikeOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	h := publicRoutes(newHandler(newService(t)))
	a, _ := member(t)
	suspended, _ := member(t)
	deleted, _ := member(t)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, suspended.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, deleted.ID); err != nil {
		t.Fatal(err)
	}
	wrong := dbtest.Unique("Wr0ng-Secret")
	login := func(email, password string) *httptest.ResponseRecorder {
		t.Helper()
		return newBrowser(t, h).do(http.MethodPost, "/auth/login", loginBody(email, password))
	}

	want := login(a.Email, wrong)
	if !answered(want, http.StatusUnauthorized, CodeInvalidCredentials) {
		t.Fatalf("sign in with the wrong password: %d %s, want 401 %s", want.Code, want.Body.String(), CodeInvalidCredentials)
	}
	for _, tc := range []struct{ name, email, password string }{
		{"an address with no account", dbtest.Unique("nobody") + "@example.test", wrong},
		{"a suspended account's wrong password", suspended.Email, wrong},
		{"a deleted account's wrong password", deleted.Email, wrong},
		{"a deleted account's right password", deleted.Email, testPassword},
	} {
		if rec := login(tc.email, tc.password); rec.Code != want.Code || rec.Body.String() != want.Body.String() {
			t.Errorf("sign in with %s: %d %s, want the wrong password's %d %s", tc.name, rec.Code, rec.Body.String(), want.Code, want.Body.String())
		}
	}
	if rec := login(suspended.Email, testPassword); !answered(rec, http.StatusForbidden, errs.CodeAuthAccountInactive) {
		t.Errorf("sign in to a suspended account with the right password: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeAuthAccountInactive)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, suspended.ID, deleted.ID}); n != 0 {
		t.Errorf("refused sign-ins opened %d sessions", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND resource_id = $1
		AND metadata->>'reason' = 'wrong_password'`, a.ID); n != 1 {
		t.Errorf("the wrong password was recorded %d times, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.sign_in_failed' AND actor_user_id IS NULL
		AND metadata->>'reason' = 'unknown_account' AND metadata->>'method' = 'password' AND created_at > NOW() - INTERVAL '1 minute'`); n < 2 {
		t.Errorf("%d sign-ins to no account recorded, want the unknown and the deleted address", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE metadata::text LIKE '%' || $1 || '%'`, wrong); n != 0 {
		t.Errorf("%d audit records keep the submitted password", n)
	}
}

// TestSignInWhileTheHasherIsFull checks that a password sign-in the hasher has
// no room for is answered 503 server.overloaded with Retry-After, for an
// account and an address with none alike, and is not counted as a failure.
func TestSignInWhileTheHasherIsFull(t *testing.T) {
	b := newBrowser(t, publicRoutes(newHandler(newService(t))))
	a, _ := member(t)
	nobody := dbtest.Unique("nobody") + "@example.test"

	release := password.FillForTest()
	for _, email := range []string{a.Email, nobody} {
		rec := b.do(http.MethodPost, "/auth/login", loginBody(email, "Wrong-password-1"))
		if !answered(rec, http.StatusServiceUnavailable, errs.CodeServerOverloaded) || rec.Header().Get("Retry-After") == "" {
			t.Errorf("sign in as %s with the hasher full: %d %s (Retry-After %q), want 503 %s with Retry-After",
				email, rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"), errs.CodeServerOverloaded)
		}
	}
	release()
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_attempts_by_network WHERE email = ANY($1)`,
		[]string{strings.ToLower(a.Email), nobody}); n != 0 {
		t.Errorf("refused sign-ins counted as %d failures, want none", n)
	}
	if rec := b.do(http.MethodPost, "/auth/login", loginBody(a.Email, testPassword)); rec.Code != http.StatusOK {
		t.Errorf("right password once the hasher has room: %d %s, want 200", rec.Code, rec.Body.String())
	}
}
