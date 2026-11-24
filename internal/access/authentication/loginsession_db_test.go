//go:build integration

package authentication

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// latestLoginSessionFactor is how a's latest hosted-login session met a
// second factor ("" for none).
func latestLoginSessionFactor(t *testing.T, a dbtest.Account) string {
	t.Helper()
	var factor string
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `
		SELECT COALESCE(second_factor, '') FROM auth.login_sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1
	`, a.ID).Scan(&factor); err != nil {
		t.Fatalf("latest hosted-login session: %v", err)
	}
	return factor
}

// TestHostedSignInCookie checks the hosted login's cookie: the right password
// sets an HttpOnly, Secure, SameSite=Lax qe_ls cookie and puts no token in the
// body; the cookie stands in for a token only on the routes listed for it and
// only while the account is active and the session unexpired; and signing out
// deletes the session, clears the cookie and is recorded once.
func TestHostedSignInCookie(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	h := publicRoutes(newHandler(svc), "GET /auth/me")
	a, home := member(t)
	b := newBrowser(t, h)

	if rec := b.do(http.MethodPost, "/auth/session", loginBody(a.Email, "Wrong-password-1")); !answered(rec, http.StatusUnauthorized, CodeInvalidCredentials) || setCookie(rec, LoginSessionCookie) != nil {
		t.Fatalf("hosted sign-in with the wrong password: %d %s, want 401 and no cookie", rec.Code, rec.Body.String())
	}
	if rec := b.do(http.MethodPost, "/auth/session", map[string]any{"email": a.Email, "password": testPassword, "remember": true}); !answered(rec, http.StatusBadRequest, errs.CodeBadRequest) || setCookie(rec, LoginSessionCookie) != nil {
		t.Errorf("hosted sign-in with an unknown field: %d %s, want 400 and no cookie", rec.Code, rec.Body.String())
	}
	rec := b.do(http.MethodPost, "/auth/session", loginBody(a.Email, testPassword))
	var body map[string]any
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusOK || len(body) != 1 || body["user_id"] != a.ID.String() {
		t.Fatalf("hosted sign-in: %d %s, want 200 with the user id alone", rec.Code, rec.Body.String())
	}
	c := setCookie(rec, LoginSessionCookie)
	if c == nil || c.Value == "" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" ||
		c.MaxAge != int(loginSessionTTL.Seconds()) {
		t.Fatalf("hosted-login cookie %+v; want HttpOnly, Secure, SameSite=Lax, Path=/ for %s", c, loginSessionTTL)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE token_hash = $1 AND user_id = $2 AND host(ip) = $3
		AND second_factor IS NULL`, tokens.HashRefresh(c.Value), a.ID, b.ip); n != 1 {
		t.Error("the hosted-login session is not stored by its hash with the client's address")
	}

	var me struct {
		UserID         uuid.UUID  `json:"user_id"`
		OrganizationID uuid.UUID  `json:"organization_id"`
		Session        *uuid.UUID `json:"session_id"`
	}
	rec = b.do(http.MethodGet, "/auth/me", nil)
	dbtest.Decode(t, rec, &me)
	if rec.Code != http.StatusOK || me.UserID != a.ID || me.OrganizationID != home || me.Session != nil {
		t.Errorf("me with the cookie: %d %+v, want %s in %s with no API session", rec.Code, me, a.ID, home)
	}
	if rec := b.do(http.MethodGet, "/auth/sessions", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("a route not listed for the cookie: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if rec := b.do(http.MethodGet, "/auth/me", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("the cookie of a suspended account: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'active' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}

	rec = b.do(http.MethodDelete, "/auth/session", nil)
	if cleared := setCookie(rec, LoginSessionCookie); rec.Code != http.StatusNoContent || cleared == nil || cleared.MaxAge >= 0 || !cleared.HttpOnly {
		t.Fatalf("sign out of the hosted login: %d, cookie %+v; want 204 and the cookie cleared", rec.Code, cleared)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d hosted-login sessions survived signing out", n)
	}
	b.cookies[LoginSessionCookie] = c
	if rec := b.do(http.MethodGet, "/auth/me", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("the cookie after signing out: %d, want 401", rec.Code)
	}
	b.cookies[LoginSessionCookie] = c
	if rec := b.do(http.MethodDelete, "/auth/session", nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out again with the ended cookie: %d, want 204", rec.Code)
	}
	if rec := newBrowser(t, h).do(http.MethodDelete, "/auth/session", nil); rec.Code != http.StatusNoContent {
		t.Errorf("sign out with no cookie: %d, want 204", rec.Code)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.signed_out' AND actor_user_id = $1
		AND organization_id = $2 AND metadata->>'initiated_by' = $3`, a.ID, home, SignOutByHostedLogin); n != 1 {
		t.Errorf("signing out was recorded %d times, want once", n)
	}

	raw, err := svc.CreateLoginSession(ctx, a.ID, "", testUserAgent)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := svc.ResolveLoginSession(ctx, raw); err != nil || id != a.ID {
		t.Fatalf("resolve a live cookie: %s, %v", id, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE auth.login_sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, tokens.HashRefresh(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveLoginSession(ctx, raw); !errors.Is(err, errs.ErrUnauthorized) {
		t.Errorf("resolve an expired cookie: %v, want %v", err, errs.ErrUnauthorized)
	}
	b.cookies[LoginSessionCookie] = &http.Cookie{Name: LoginSessionCookie, Value: raw}
	if rec := b.do(http.MethodGet, "/auth/me", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("an expired cookie: %d, want 401", rec.Code)
	}
}

// TestHostedSecondFactor checks the hosted two-step sign-in: a wrong code sets
// no cookie; the right code sets it, records the session as having met a
// second factor, which counts as a fresh step-up and satisfies an
// organization requiring one, and remembers the device in an HttpOnly cookie
// only when asked and where the organization remembers devices.
func TestHostedSecondFactor(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.mfa = heldFactor{code: "135790"}
	a, home := member(t)
	svc.devicePolicy = rememberIn(home)
	h := publicRoutes(newHandler(svc))
	complete := func(b *browser, token string, remember bool) *httptest.ResponseRecorder {
		t.Helper()
		rec := b.do(http.MethodPost, "/auth/session/mfa", map[string]any{"mfa_token": token, "code": "135790", "remember": remember})
		if rec.Code != http.StatusOK || setCookie(rec, LoginSessionCookie) == nil {
			t.Fatalf("complete the hosted challenge: %d %s, want 200 and the session cookie", rec.Code, rec.Body.String())
		}
		return rec
	}

	b := newBrowser(t, h)
	token := hostedChallenge(t, b, a)
	if rec := b.do(http.MethodPost, "/auth/session/mfa", map[string]any{"mfa_token": token, "code": "000000"}); !answered(rec, http.StatusUnauthorized, errs.CodeMFACodeInvalid) || setCookie(rec, LoginSessionCookie) != nil {
		t.Fatalf("complete with a wrong code: %d %s, want 401 and no cookie", rec.Code, rec.Body.String())
	}
	rec := complete(b, token, true)
	device := setCookie(rec, TrustedDeviceCookie)
	if device == nil || device.Value == "" || !device.HttpOnly || !device.Secure || device.SameSite != http.SameSiteLaxMode ||
		device.MaxAge != int(trustedDeviceTTL.Seconds()) {
		t.Fatalf("remembered-device cookie %+v; want HttpOnly, Secure, SameSite=Lax for %s", device, trustedDeviceTTL)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE token_hash = $1 AND user_id = $2 AND organization_id = $3
		AND label = $4`, tokens.HashRefresh(device.Value), a.ID, home, testUserAgent); n != 1 {
		t.Error("the remembered device is not stored by its hash for the person and organization")
	}
	if factor := latestLoginSessionFactor(t, a); factor != secondFactorMFA {
		t.Errorf("the hosted-login session records second factor %q, want %q", factor, secondFactorMFA)
	}
	if _, _, at, err := svc.resolveLoginSession(ctx, b.cookies[LoginSessionCookie].Value); err != nil || at.IsZero() {
		t.Errorf("a session that met a second factor resolves with sign-in time %v, %v; want it, as a step-up", at, err)
	}
	strict := requiringOrganization(t, a)
	if err := svc.LoginSessionFactorShortfall(ctx, sessionIDOf(t, svc, b.cookies[LoginSessionCookie].Value), a.ID, strict); err != nil {
		t.Errorf("a session that met a second factor entering an organization requiring one: %v", err)
	}
	passwordOnly, err := svc.CreateLoginSession(ctx, a.ID, "", testUserAgent)
	if err != nil {
		t.Fatal(err)
	}
	stranger, _ := member(t)
	for _, tc := range []struct {
		name    string
		session uuid.UUID
		userID  uuid.UUID
		want    error
	}{
		{"a session that met none", sessionIDOf(t, svc, passwordOnly), a.ID, errs.ErrStepUpRequired},
		{"someone else's session", sessionIDOf(t, svc, passwordOnly), stranger.ID, errs.ErrUnauthorized},
		{"an unknown session", uuid.New(), a.ID, errs.ErrUnauthorized},
	} {
		if err := svc.LoginSessionFactorShortfall(ctx, tc.session, tc.userID, strict); !errors.Is(err, tc.want) {
			t.Errorf("%s entering an organization requiring a factor: %v, want %v", tc.name, err, tc.want)
		}
	}

	b = newBrowser(t, h)
	if rec := complete(b, hostedChallenge(t, b, a), false); setCookie(rec, TrustedDeviceCookie) != nil {
		t.Error("a device was remembered without being asked")
	}
	svc.devicePolicy = rememberIn(uuid.Nil)
	b = newBrowser(t, h)
	if rec := complete(b, hostedChallenge(t, b, a), true); setCookie(rec, TrustedDeviceCookie) != nil {
		t.Error("a device was remembered where the organization remembers none")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 1 {
		t.Errorf("%d devices remembered, want the one asked for where allowed", n)
	}
}

// TestSuspensionEndsTheHostedLogin checks that once an account is suspended,
// as SCIM deprovisioning does it, its hosted-login cookie no longer resolves
// on the resolvers the OIDC and SAML sign-ins use.
func TestSuspensionEndsTheHostedLogin(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	svc := newService(t)
	a, _ := member(t)
	raw, err := svc.CreateLoginSession(ctx, a.ID, "", testUserAgent)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE account.users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := sessionsignal.EndUserSessions(ctx, tx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ResolveLoginSession(ctx, raw); !errors.Is(err, errs.ErrUnauthorized) {
		t.Errorf("resolve a suspended account's cookie: %v, want %v", err, errs.ErrUnauthorized)
	}
	if _, _, _, err := svc.ResolveLoginSessionAt(ctx, raw); !errors.Is(err, errs.ErrUnauthorized) {
		t.Errorf("resolve a suspended account's cookie with its sign-in time: %v, want %v", err, errs.ErrUnauthorized)
	}
}

// TestHostedSignInsAreRecorded checks that every hosted sign-in records the
// auth.login_succeeded event an API sign-in does, once, for its hosted-login
// session, by method and against the organization signed in to, so the
// dashboard counts it; and that signing up, which signs the account in, does
// too.
func TestHostedSignInsAreRecorded(t *testing.T) {
	ctx := dbtest.Context(t)
	recorded := func(t *testing.T, a dbtest.Account, organization uuid.UUID, method string) {
		t.Helper()
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND actor_user_id = $1`, a.ID); n != 1 {
			t.Errorf("%d sign-ins recorded, want 1", n)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events e
			JOIN auth.login_sessions s ON s.id = e.resource_id AND s.user_id = e.actor_user_id
			WHERE e.action = 'auth.login_succeeded' AND e.resource_type = 'login_session' AND e.actor_user_id = $1
			  AND e.organization_id = $2 AND e.metadata->>'method' = $3`, a.ID, organization, method); n != 1 {
			t.Errorf("the hosted sign-in is not recorded as %s to %s for its session", method, organization)
		}
	}

	t.Run("password", func(t *testing.T) {
		svc := newService(t)
		a, home := member(t)
		res, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: testPassword, IP: freshIP()}, testUserAgent, "", "")
		if err != nil || res.RawCookie == "" {
			t.Fatalf("hosted sign-in: %+v, %v", res, err)
		}
		recorded(t, a, home, "password")
	})
	t.Run("second factor", func(t *testing.T) {
		svc := newService(t)
		svc.mfa = heldFactor{code: "246810"}
		a, home := member(t)
		res, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: testPassword, IP: freshIP()}, testUserAgent, "", "")
		if err != nil || !res.MFARequired {
			t.Fatalf("hosted sign-in holding a factor: %+v, %v; want a challenge", res, err)
		}
		if _, _, cookie, err := svc.CompleteMFALoginSession(ctx, res.MFAToken, "246810", freshIP(), testUserAgent); err != nil || cookie == "" {
			t.Fatalf("complete the hosted challenge: %q, %v", cookie, err)
		}
		recorded(t, a, home, "password_mfa")
	})
	t.Run("passkey", func(t *testing.T) {
		svc := newService(t)
		a, home := member(t)
		if _, err := svc.CreatePasskeyLoginSession(ctx, a.ID, freshIP(), testUserAgent); err != nil {
			t.Fatal(err)
		}
		recorded(t, a, home, "passkey")
	})
	t.Run("social", func(t *testing.T) {
		svc := newService(t)
		a, _ := member(t)
		served := dbtest.Organization(t)
		dbtest.Assign(t, a.ID, served, dbtest.Role(t, served))
		res, err := svc.BeginSocialLoginSession(ctx, a.ID, served, freshIP(), testUserAgent, "", "")
		if err != nil || res.RawCookie == "" {
			t.Fatalf("hosted social sign-in: %+v, %v", res, err)
		}
		recorded(t, a, served, "social")
	})
	t.Run("magic link", func(t *testing.T) {
		svc := newService(t)
		a, organization := member(t)
		res, err := svc.BeginMagicLinkSession(ctx, a.ID, organization, freshIP(), testUserAgent, "", "")
		if err != nil || res.RawCookie == "" {
			t.Fatalf("hosted magic link: %+v, %v", res, err)
		}
		recorded(t, a, organization, "magic_link")
	})
	t.Run("sign-up", func(t *testing.T) {
		svc := newService(t)
		svc.regPolicy = anyPassword{}
		pair, u, _, err := svc.Signup(ctx, SignupInput{Email: dbtest.Unique("signup") + "@example.test", Password: testPassword, IP: freshIP(), UserAgent: testUserAgent})
		if err != nil {
			t.Fatalf("sign up: %v", err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND actor_user_id = $1
			AND resource_type = 'session' AND resource_id = $2 AND organization_id IS NULL AND metadata->>'method' = 'password'`, u.ID, pair.SessionID); n != 1 {
			t.Error("signing up is not recorded as a password sign-in to no organization")
		}
	})
}

// TestHostedLoginSessionRefusedFromABlockedAddress checks that no hosted-login
// session is opened from an address the account's own organization refuses:
// not by a passkey, a password, nor a password through another organization's
// application whose rules allow the address, and that each refusal is
// recorded; from an allowed address the session opens.
func TestHostedLoginSessionRefusedFromABlockedAddress(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.addresses = ipallow.NewService(dbtest.Pool(t))
	a, home := member(t)
	enforceAddressRules(t, home) // only 192.0.2.0/24
	other := dbtest.Organization(t)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, other, client); err != nil {
		t.Fatal(err)
	}
	const blocked = "198.51.100.7"
	if _, err := svc.CreatePasskeyLoginSession(ctx, a.ID, blocked, testUserAgent); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("a passkey sign-in from a blocked address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if _, err := svc.CreateLoginSession(ctx, a.ID, blocked, testUserAgent); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("a password sign-in from a blocked address: %v, want %v", err, errs.ErrAuthAddressNotAllowed)
	}
	if res, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: testPassword, IP: blocked, ClientID: client}, testUserAgent, "", ""); !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
		t.Errorf("a password sign-in through another organization's application from a blocked address: %+v, %v; want %v", res, err, errs.ErrAuthAddressNotAllowed)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.login_sessions WHERE user_id = $1`, a.ID); n != 0 {
		t.Errorf("%d hosted-login sessions opened from a blocked address", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.address_refused' AND organization_id = $1 AND metadata->>'address' = $2`, home, blocked); n != 3 {
		t.Errorf("%d refusals recorded, want 3", n)
	}
	if _, err := svc.CreatePasskeyLoginSession(ctx, a.ID, "192.0.2.10", testUserAgent); err != nil {
		t.Errorf("a passkey sign-in from an allowed address: %v", err)
	}
}
