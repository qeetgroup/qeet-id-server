//go:build integration

package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// rememberIn is a device policy under which only its organisation remembers
// devices, for the default time.
type rememberIn uuid.UUID

func (r rememberIn) RememberDeviceEnabled(_ context.Context, tenantID uuid.UUID) (bool, error) {
	return tenantID == uuid.UUID(r), nil
}

func (r rememberIn) RememberDevicePolicy(_ context.Context, tenantID uuid.UUID) (bool, time.Duration, error) {
	return tenantID == uuid.UUID(r), 0, nil
}

// hostedChallenge starts a hosted sign-in as a from b, failing t unless it
// answers a challenge and sets no session cookie, and returns its token.
func hostedChallenge(t *testing.T, b *browser, a dbtest.Account) string {
	t.Helper()
	rec := b.do(http.MethodPost, "/auth/session", loginBody(a.Email, testPassword))
	var body struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusOK || !body.MFARequired || body.MFAToken == "" || setCookie(rec, LoginSessionCookie) != nil {
		t.Fatalf("hosted sign-in holding a second factor: %d %s, want a challenge and no cookie", rec.Code, rec.Body.String())
	}
	return body.MFAToken
}

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

	if rec := b.do(http.MethodPost, "/auth/session", loginBody(a.Email, "Wrong-password-1")); !answered(rec, http.StatusUnauthorized, errs.CodeAuthInvalidCredentials) || setCookie(rec, LoginSessionCookie) != nil {
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
		UserID   uuid.UUID  `json:"user_id"`
		TenantID uuid.UUID  `json:"tenant_id"`
		Session  *uuid.UUID `json:"session_id"`
	}
	rec = b.do(http.MethodGet, "/auth/me", nil)
	dbtest.Decode(t, rec, &me)
	if rec.Code != http.StatusOK || me.UserID != a.ID || me.TenantID != home || me.Session != nil {
		t.Errorf("me with the cookie: %d %+v, want %s in %s with no API session", rec.Code, me, a.ID, home)
	}
	if rec := b.do(http.MethodGet, "/auth/sessions", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("a route not listed for the cookie: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
		t.Fatal(err)
	}
	if rec := b.do(http.MethodGet, "/auth/me", nil); !answered(rec, http.StatusUnauthorized, errs.CodeUnauthorized) {
		t.Errorf("the cookie of a suspended account: %d %s, want 401", rec.Code, rec.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET status = 'active' WHERE id = $1`, a.ID); err != nil {
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
		AND tenant_id = $2 AND metadata->>'initiated_by' = $3`, a.ID, home, SignOutByHostedLogin); n != 1 {
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
// organisation requiring one, and remembers the device in an HttpOnly cookie
// only when asked and where the organisation remembers devices.
func TestHostedSecondFactor(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetMFA(heldFactor{code: "135790"})
	a, home := member(t)
	svc.SetDevicePolicy(rememberIn(home))
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
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE token_hash = $1 AND user_id = $2 AND tenant_id = $3
		AND label = $4`, tokens.HashRefresh(device.Value), a.ID, home, testUserAgent); n != 1 {
		t.Error("the remembered device is not stored by its hash for the person and organisation")
	}
	if factor := latestLoginSessionFactor(t, a); factor != secondFactorMFA {
		t.Errorf("the hosted-login session records second factor %q, want %q", factor, secondFactorMFA)
	}
	if _, _, at, err := svc.resolveLoginSession(ctx, b.cookies[LoginSessionCookie].Value); err != nil || at.IsZero() {
		t.Errorf("a session that met a second factor resolves with sign-in time %v, %v; want it, as a step-up", at, err)
	}
	strict := requiringOrganisation(t, a)
	if err := svc.LoginSessionFactorShortfall(ctx, sessionIDOf(t, svc, b.cookies[LoginSessionCookie].Value), a.ID, strict); err != nil {
		t.Errorf("a session that met a second factor entering an organisation requiring one: %v", err)
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
			t.Errorf("%s entering an organisation requiring a factor: %v, want %v", tc.name, err, tc.want)
		}
	}

	b = newBrowser(t, h)
	if rec := complete(b, hostedChallenge(t, b, a), false); setCookie(rec, TrustedDeviceCookie) != nil {
		t.Error("a device was remembered without being asked")
	}
	svc.SetDevicePolicy(rememberIn(uuid.Nil))
	b = newBrowser(t, h)
	if rec := complete(b, hostedChallenge(t, b, a), true); setCookie(rec, TrustedDeviceCookie) != nil {
		t.Error("a device was remembered where the organisation remembers none")
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = $1`, a.ID); n != 1 {
		t.Errorf("%d devices remembered, want the one asked for where allowed", n)
	}
}

// sessionIDOf returns the id of the hosted-login session behind cookie raw.
func sessionIDOf(t *testing.T, svc *Service, raw string) uuid.UUID {
	t.Helper()
	id, _, err := svc.ResolveLoginSessionWithID(dbtest.Context(t), raw)
	if err != nil {
		t.Fatalf("resolve the hosted-login session: %v", err)
	}
	return id
}

// requiringOrganisation creates an organisation that requires a second factor
// at once and makes a a member of it.
func requiringOrganisation(t *testing.T, a dbtest.Account) uuid.UUID {
	t.Helper()
	tenant := dbtest.Tenant(t)
	dbtest.Assign(t, a.ID, tenant, dbtest.Role(t, tenant))
	if _, err := dbtest.Pool(t).Exec(dbtest.Context(t), `
		INSERT INTO tenant.security_policies (tenant_id, mfa_enforcement, mfa_grace_days, mfa_enforced_since)
		VALUES ($1, 'required', 0, NOW())
	`, tenant); err != nil {
		t.Fatalf("require a second factor: %v", err)
	}
	return tenant
}

// TestRememberedDeviceSkipsTheFactor checks that a remembered device skips the
// second factor at the hosted sign-in, recorded as such, for its own person
// and organisation only: not for another person, not with trust from another
// organisation, not on a risky sign-in, not once the organisation stops
// remembering devices or the device expires, and not once it is forgotten;
// and that a session it opens is no fresh step-up, unlike a passkey's.
func TestRememberedDeviceSkipsTheFactor(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetMFA(heldFactor{code: "135790"})
	risk := &riskStub{}
	svc.SetRiskAssessor(risk)
	a, home := member(t)
	svc.SetDevicePolicy(rememberIn(home))
	colleague := dbtest.User(t, home, home)
	dbtest.SetPassword(t, colleague.ID, testPassword)
	other := dbtest.Tenant(t)
	h := publicRoutes(newHandler(svc))
	device, err := svc.CreateTrustedDevice(ctx, a.ID, home, testUserAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	elsewhere, err := svc.CreateTrustedDevice(ctx, a.ID, other, testUserAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signInOn := func(u dbtest.Account, raw string) (*httptest.ResponseRecorder, *browser) {
		t.Helper()
		b := newBrowser(t, h)
		b.cookies[TrustedDeviceCookie] = &http.Cookie{Name: TrustedDeviceCookie, Value: raw}
		return b.do(http.MethodPost, "/auth/session", loginBody(u.Email, testPassword)), b
	}
	skipped := func(rec *httptest.ResponseRecorder) bool {
		return rec.Code == http.StatusOK && setCookie(rec, LoginSessionCookie) != nil
	}

	rec, b := signInOn(a, device)
	if !skipped(rec) {
		t.Fatalf("sign in on the remembered device: %d %s, want the session cookie at once", rec.Code, rec.Body.String())
	}
	if factor := latestLoginSessionFactor(t, a); factor != secondFactorTrustedDevice {
		t.Errorf("the hosted-login session records second factor %q, want %q", factor, secondFactorTrustedDevice)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.trusted_device_used' AND actor_user_id = $1 AND tenant_id = $2`, a.ID, home); n != 1 {
		t.Errorf("the device's use was recorded %d times, want once", n)
	}
	raw := b.cookies[LoginSessionCookie].Value
	if _, _, at, err := svc.resolveLoginSession(ctx, raw); err != nil || !at.IsZero() {
		t.Errorf("a session the device opened resolves with sign-in time %v, %v; want none, as no step-up", at, err)
	}
	if _, err := svc.CreatePasskeyLoginSession(ctx, a.ID, "", testUserAgent); err != nil {
		t.Fatal(err)
	}
	if factor := latestLoginSessionFactor(t, a); factor != secondFactorPasskey {
		t.Errorf("a passkey hosted-login session records second factor %q, want %q", factor, secondFactorPasskey)
	}

	for _, tc := range []struct {
		name  string
		u     dbtest.Account
		raw   string
		setup func()
	}{
		{"another person", colleague, device, func() {}},
		{"trust from another organisation", a, elsewhere, func() {}},
		{"a risky sign-in", a, device, func() { risk.risky = true }},
		{"an organisation that stopped remembering devices", a, device, func() { svc.SetDevicePolicy(rememberIn(uuid.Nil)) }},
		{"an expired device", a, device, func() {
			if _, err := dbtest.Pool(t).Exec(ctx, `UPDATE auth.trusted_devices SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`, tokens.HashRefresh(device)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			defer func() {
				risk.risky = false
				svc.SetDevicePolicy(rememberIn(home))
			}()
			if rec, _ := signInOn(tc.u, tc.raw); skipped(rec) || rec.Code != http.StatusOK {
				t.Errorf("sign in: %d %s, want a challenge", rec.Code, rec.Body.String())
			}
		})
	}
	fresh, err := svc.CreateTrustedDevice(ctx, a.ID, home, testUserAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := svc.ForgetTrustedDevices(ctx, ForgetTrustedDevicesInput{UserID: a.ID}); err != nil || n != 3 {
		t.Fatalf("forget every device: %d, %v; want 3", n, err)
	}
	if rec, _ := signInOn(a, fresh); skipped(rec) {
		t.Error("a forgotten device still skips the second factor")
	}
}

// TestTrustedDevicesOverHTTP checks the views of remembered devices: a person
// lists theirs in every organisation, marked where it is the requesting one,
// and forgets one or all, never another person's; an administrator sees,
// counts and forgets only those remembered in their own organisation, and for
// its members only.
func TestTrustedDevicesOverHTTP(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a, home := member(t)
	other := dbtest.Tenant(t)
	dbtest.Assign(t, a.ID, other, dbtest.Role(t, other))
	colleague := dbtest.User(t, home, home)
	outsider, _ := member(t)
	admin := dbtest.User(t, home, home)
	remember := func(userID, tenant uuid.UUID) (string, uuid.UUID) {
		t.Helper()
		raw, err := svc.CreateTrustedDevice(ctx, userID, tenant, testUserAgent, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		var id uuid.UUID
		if err := dbtest.Pool(t).QueryRow(ctx, `SELECT id FROM auth.trusted_devices WHERE token_hash = $1`, tokens.HashRefresh(raw)).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return raw, id
	}
	current, atHome := remember(a.ID, home)
	_, atOther := remember(a.ID, other)
	_, colleagues := remember(colleague.ID, home)
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.trusted_devices (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, NOW() - INTERVAL '1 minute')`, a.ID, home, dbtest.Unique("expired")); err != nil {
		t.Fatal(err)
	}
	type listed struct {
		Items []TrustedDevice `json:"items"`
	}
	forgotten := func(rec *httptest.ResponseRecorder) int {
		t.Helper()
		var got struct {
			Forgotten int `json:"forgotten"`
		}
		dbtest.Decode(t, rec, &got)
		if rec.Code != http.StatusOK {
			t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
		}
		return got.Forgotten
	}

	own := newBrowser(t, dbtest.Serve(dbtest.Principal(a.ID, home), newHandler(svc).MountAuthed))
	own.cookies[TrustedDeviceCookie] = &http.Cookie{Name: TrustedDeviceCookie, Value: current}
	var mine listed
	dbtest.Decode(t, own.do(http.MethodGet, "/auth/trusted-devices", nil), &mine)
	marked := map[uuid.UUID]bool{}
	for _, d := range mine.Items {
		marked[d.ID] = d.Current
		if d.Device != "Chrome on macOS" || d.DeviceKind != "desktop" {
			t.Errorf("device named %q (%s), want Chrome on macOS (desktop)", d.Device, d.DeviceKind)
		}
	}
	if len(marked) != 2 || !marked[atHome] || marked[atOther] {
		t.Errorf("own devices %v; want the live ones in both organisations, the requesting one marked", marked)
	}
	if rec := own.do(http.MethodDelete, "/auth/trusted-devices/"+colleagues.String(), nil); !answered(rec, http.StatusNotFound, errs.CodeNotFound) {
		t.Errorf("forget another person's device: %d %s, want 404", rec.Code, rec.Body.String())
	}
	if rec := own.do(http.MethodDelete, "/auth/trusted-devices/not-a-device", nil); !answered(rec, http.StatusBadRequest, errs.CodeBadRequest) {
		t.Errorf("forget a malformed device id: %d, want 400", rec.Code)
	}

	adm := newBrowser(t, dbtest.Serve(dbtest.Principal(admin.ID, home), newHandler(svc).MountAuthed))
	var count TrustedDeviceSummary
	dbtest.Decode(t, adm.do(http.MethodGet, "/auth/trusted-devices/count", nil), &count)
	if count != (TrustedDeviceSummary{Devices: 2, Users: 2}) {
		t.Errorf("organisation's device count %+v, want 2 devices of 2 people", count)
	}
	var theirs listed
	dbtest.Decode(t, adm.do(http.MethodGet, "/users/"+a.ID.String()+"/trusted-devices", nil), &theirs)
	if len(theirs.Items) != 1 || theirs.Items[0].ID != atHome || theirs.Items[0].Current {
		t.Errorf("a member's devices as the administrator sees them: %+v, want only the one remembered here", theirs.Items)
	}
	for _, tc := range []struct {
		name, method, path string
		status             int
	}{
		{"list an outsider's devices", http.MethodGet, "/users/" + outsider.ID.String() + "/trusted-devices", http.StatusNotFound},
		{"list for a malformed id", http.MethodGet, "/users/not-a-user/trusted-devices", http.StatusBadRequest},
		{"forget a member's device in another organisation", http.MethodDelete, "/users/" + a.ID.String() + "/trusted-devices/" + atOther.String(), http.StatusNotFound},
		{"forget an outsider's devices", http.MethodDelete, "/users/" + outsider.ID.String() + "/trusted-devices", http.StatusNotFound},
		{"forget a malformed device id", http.MethodDelete, "/users/" + a.ID.String() + "/trusted-devices/not-a-device", http.StatusBadRequest},
	} {
		if rec := adm.do(tc.method, tc.path, nil); rec.Code != tc.status {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.status)
		}
	}
	if n := forgotten(adm.do(http.MethodDelete, "/users/"+a.ID.String()+"/trusted-devices/"+atHome.String(), nil)); n != 1 {
		t.Errorf("forget a member's device: %d forgotten, want 1", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.trusted_device_revoked' AND resource_id = $1
		AND tenant_id = $2 AND actor_user_id = $3`, atHome, home, admin.ID); n != 1 {
		t.Errorf("forgetting the device was audited %d times, want once by the administrator", n)
	}
	if n := forgotten(adm.do(http.MethodDelete, "/users/"+a.ID.String()+"/trusted-devices", nil)); n != 1 {
		t.Errorf("forget all of a member's devices here: %d forgotten, want the expired one left", n)
	}
	if n := forgotten(own.do(http.MethodDelete, "/auth/trusted-devices", nil)); n != 1 {
		t.Errorf("forget all own devices: %d forgotten, want the one in the other organisation", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.trusted_devices WHERE user_id = ANY($1)`, []uuid.UUID{a.ID, colleague.ID}); n != 1 {
		t.Errorf("%d devices left, want the colleague's alone", n)
	}
}

// TestMagicLinkSignIn checks that a consumed magic link signs in like a
// password: an inactive account or organisation is refused, a held second
// factor is asked for and the session it opens recorded as magic_link_mfa, a
// risky link sign-in, having proved the email, asks for no emailed code, and
// the hosted form skips the factor only on a device remembered for the link's
// organisation.
func TestMagicLinkSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	ip := freshIP()

	t.Run("signs in", func(t *testing.T) {
		svc := newService(t)
		a, tenant := member(t)
		res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, tenant, ip, testUserAgent)
		if err != nil || res.Pair == nil || res.Pair.UserID != a.ID {
			t.Fatalf("sign in: %+v, %v", res, err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1
			AND metadata->>'method' = 'magic_link'`, res.Pair.SessionID); n != 1 {
			t.Error("the sign-in was not audited as a magic link")
		}
	})
	t.Run("inactive", func(t *testing.T) {
		svc := newService(t)
		for _, tc := range []struct {
			name, change string
			want         error
		}{
			{"suspended account", `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, errs.ErrAuthAccountInactive},
			{"suspended organisation", `UPDATE tenant.tenants SET status = 'suspended' WHERE id = (SELECT tenant_id FROM "user".users WHERE id = $1)`, errs.ErrAuthTenantInactive},
		} {
			a, tenant := member(t)
			if _, err := pool.Exec(ctx, tc.change, a.ID); err != nil {
				t.Fatal(err)
			}
			if res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, tenant, ip, testUserAgent); !errors.Is(err, tc.want) || res != nil {
				t.Errorf("%s: %+v, %v; want %v", tc.name, res, err, tc.want)
			}
		}
	})
	t.Run("second factor", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(heldFactor{code: "975310"})
		a, tenant := member(t)
		res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, tenant, ip, testUserAgent)
		if err != nil || res.Pair != nil || !res.MFARequired {
			t.Fatalf("sign in holding a factor: %+v, %v; want a challenge", res, err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM auth.mfa_login_challenges WHERE id = $1 AND first_factor = 'magic_link'`, res.MFAToken); n != 1 {
			t.Error("the challenge does not record the magic link")
		}
		pair, err := svc.CompleteMFALogin(ctx, res.MFAToken, "975310", ip, testUserAgent)
		if err != nil {
			t.Fatalf("complete: %v", err)
		}
		if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.login_succeeded' AND resource_id = $1
			AND metadata->>'method' = 'magic_link_mfa'`, pair.SessionID); n != 1 {
			t.Error("the completed sign-in was not audited as magic_link_mfa")
		}
	})
	t.Run("risky", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(noFactors{})
		svc.SetRiskAssessor(&riskStub{risky: true})
		a, tenant := member(t)
		if res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, tenant, ip, testUserAgent); err != nil || res.Pair == nil {
			t.Errorf("risky link sign-in: %+v, %v; want a session, the email being proved", res, err)
		}
	})
	t.Run("hosted", func(t *testing.T) {
		svc := newService(t)
		svc.SetMFA(heldFactor{code: "975310"})
		a, tenant := member(t)
		svc.SetDevicePolicy(rememberIn(tenant))
		device, err := svc.CreateTrustedDevice(ctx, a.ID, tenant, testUserAgent, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		other := dbtest.Tenant(t)
		if res, err := svc.BeginMagicLinkSession(ctx, a.ID, tenant, ip, testUserAgent, device, ""); err != nil || res.RawCookie == "" {
			t.Errorf("hosted link on the remembered device: %+v, %v; want the session cookie", res, err)
		}
		res, err := svc.BeginMagicLinkSession(ctx, a.ID, other, ip, testUserAgent, device, "")
		if err != nil || res.RawCookie != "" || !res.MFARequired {
			t.Fatalf("hosted link for another organisation on the device: %+v, %v; want a challenge", res, err)
		}
		userID, _, cookie, err := svc.CompleteMFALoginSession(ctx, res.MFAToken, "975310", ip, testUserAgent)
		if err != nil || userID != a.ID || cookie == "" {
			t.Errorf("complete the hosted challenge: %s %q, %v", userID, cookie, err)
		}
	})
}

// TestTokenReuseOnATenantlessSession checks that the theft of a tenant-less
// session's refresh token is recorded as an event of no organisation, like
// the session's other records, rather than of an organisation that doesn't
// exist.
func TestTokenReuseOnATenantlessSession(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	a := dbtest.User(t, uuid.Nil)
	pair, err := svc.IssuePair(ctx, a.ID, uuid.Nil, "", "test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Fatalf("reuse the spent token: %v, want %v", err, errs.ErrAuthSessionRevoked)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.token_reuse_detected' AND resource_id = $1
		AND tenant_id IS NULL`, pair.SessionID); n != 1 {
		t.Errorf("the reuse was recorded with no organisation %d times, want once", n)
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
	if _, err := tx.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, a.ID); err != nil {
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

// TestRememberedDeviceForAnotherOrganisationsApplication checks that a hosted
// sign-in to the application of an organisation that requires a second factor
// and remembers no devices asks for the factor, even on a device the person's
// own organisation remembers, and that the session it opens does not satisfy
// that organisation's requirement.
func TestRememberedDeviceForAnotherOrganisationsApplication(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetMFA(heldFactor{code: "135790"})
	a, home := member(t)
	svc.SetDevicePolicy(rememberIn(home))
	strict := requiringOrganisation(t, a)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
		t.Fatal(err)
	}
	device, err := svc.CreateTrustedDevice(ctx, a.ID, home, testUserAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.BeginLoginSession(ctx, SignInAttempt{Email: a.Email, Password: testPassword, IP: freshIP(), ClientID: client}, testUserAgent, device, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.MFARequired || res.RawCookie != "" {
		t.Errorf("sign in to the strict organisation's application on a device remembered at home: %+v, want a challenge", res)
	}
	if res.RawCookie != "" {
		if err := svc.LoginSessionFactorShortfall(ctx, sessionIDOf(t, svc, res.RawCookie), a.ID, strict); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Errorf("the session entering the strict organisation: %v, want %v", err, errs.ErrStepUpRequired)
		}
	}
}
