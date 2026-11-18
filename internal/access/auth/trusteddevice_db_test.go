//go:build integration

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRememberedDeviceSkipsTheFactor checks that a remembered device skips the
// second factor at the hosted sign-in, recorded as such, for its own person
// and organization only: not for another person, not with trust from another
// organization, not on a risky sign-in, not once the organization stops
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
	other := dbtest.Organization(t)
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
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE action = 'auth.trusted_device_used' AND actor_user_id = $1 AND organization_id = $2`, a.ID, home); n != 1 {
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
		{"trust from another organization", a, elsewhere, func() {}},
		{"a risky sign-in", a, device, func() { risk.risky = true }},
		{"an organization that stopped remembering devices", a, device, func() { svc.SetDevicePolicy(rememberIn(uuid.Nil)) }},
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

// TestRememberedDeviceForAnotherOrganizationsApplication checks that a hosted
// sign-in to the application of an organization that requires a second factor
// and remembers no devices asks for the factor, even on a device the person's
// own organization remembers, and that the session it opens does not satisfy
// that organization's requirement.
func TestRememberedDeviceForAnotherOrganizationsApplication(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := newService(t)
	svc.SetMFA(heldFactor{code: "135790"})
	a, home := member(t)
	svc.SetDevicePolicy(rememberIn(home))
	strict := requiringOrganization(t, a)
	client := dbtest.Unique("app")
	if _, err := dbtest.Pool(t).Exec(ctx, `INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, $2)`, strict, client); err != nil {
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
		t.Errorf("sign in to the strict organization's application on a device remembered at home: %+v, want a challenge", res)
	}
	if res.RawCookie != "" {
		if err := svc.LoginSessionFactorShortfall(ctx, sessionIDOf(t, svc, res.RawCookie), a.ID, strict); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Errorf("the session entering the strict organization: %v, want %v", err, errs.ErrStepUpRequired)
		}
	}
}
