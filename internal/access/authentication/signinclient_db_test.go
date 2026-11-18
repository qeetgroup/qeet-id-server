//go:build integration

package authentication

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestASignInSaysWhichApplicationItWasFor checks that a hosted sign-in records
// the registered application it was for, named by the password sign-in's
// client_id or by the cookie the authorization endpoint sets, and records
// none for an application that isn't registered.
func TestASignInSaysWhichApplicationItWasFor(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	organization := dbtest.Organization(t)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, 'Payroll')`, organization, client); err != nil {
		t.Fatal(err)
	}
	recorded := func(userID any) int {
		t.Helper()
		return dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.login_succeeded'
			AND metadata->>'client_id' = $2 AND metadata->>'client_name' = 'Payroll'`, userID, client)
	}

	byPassword := dbtest.User(t, organization, organization)
	dbtest.SetPassword(t, byPassword.ID, testPassword)
	if _, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: byPassword.Email, Password: testPassword, IP: freshIP(), ClientID: client}, testUserAgent, "", ""); err != nil {
		t.Fatal(err)
	}
	if n := recorded(byPassword.ID); n != 1 {
		t.Errorf("a password sign-in for the application recorded it %d times, want once", n)
	}

	byCookie := dbtest.User(t, organization, organization)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/passkeys/login/finish", nil)
	req.AddCookie(&http.Cookie{Name: SignInClientCookie, Value: client})
	SignInClientContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if _, err := svc.CreatePasskeyLoginSession(r.Context(), byCookie.ID, freshIP(), testUserAgent); err != nil {
			t.Fatal(err)
		}
	})).ServeHTTP(httptest.NewRecorder(), req)
	if n := recorded(byCookie.ID); n != 1 {
		t.Errorf("a passkey sign-in after the authorization endpoint named the application recorded it %d times, want once", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.login_succeeded'
		AND metadata->>'second_factor' = 'passkey'`, byCookie.ID); n != 1 {
		t.Errorf("a passkey sign-in recorded its second factor %d times, want once", n)
	}

	unknown := dbtest.User(t, organization, organization)
	if _, err := svc.CreatePasskeyLoginSession(WithSignInClient(ctx, "no-such-app"), unknown.ID, freshIP(), testUserAgent); err != nil {
		t.Fatal(err)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.login_succeeded' AND metadata ? 'client_id'`, unknown.ID); n != 0 {
		t.Errorf("a sign-in naming an unregistered application recorded it %d times", n)
	}
}
