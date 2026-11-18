//go:build integration

package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestMagicLinkSignIn checks that a consumed magic link signs in like a
// password: an inactive account or organization is refused, a held second
// factor is asked for and the session it opens recorded as magic_link_mfa, a
// risky link sign-in, having proved the email, asks for no emailed code, and
// the hosted form skips the factor only on a device remembered for the link's
// organization.
func TestMagicLinkSignIn(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	ip := freshIP()

	t.Run("signs in", func(t *testing.T) {
		svc := newService(t)
		a, organization := member(t)
		res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, organization, ip, testUserAgent)
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
			{"suspended account", `UPDATE account.users SET status = 'suspended' WHERE id = $1`, errs.ErrAuthAccountInactive},
			{"suspended organization", `UPDATE organization.organizations SET status = 'suspended' WHERE id = (SELECT organization_id FROM account.users WHERE id = $1)`, ErrOrganizationInactive},
		} {
			a, organization := member(t)
			if _, err := pool.Exec(ctx, tc.change, a.ID); err != nil {
				t.Fatal(err)
			}
			if res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, organization, ip, testUserAgent); !errors.Is(err, tc.want) || res != nil {
				t.Errorf("%s: %+v, %v; want %v", tc.name, res, err, tc.want)
			}
		}
	})
	t.Run("second factor", func(t *testing.T) {
		svc := newService(t)
		svc.mfa = heldFactor{code: "975310"}
		a, organization := member(t)
		res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, organization, ip, testUserAgent)
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
		svc.mfa = noFactors{}
		svc.riskAssessor = &riskStub{risky: true}
		a, organization := member(t)
		if res, err := svc.BeginMagicLinkSignIn(ctx, a.ID, organization, ip, testUserAgent); err != nil || res.Pair == nil {
			t.Errorf("risky link sign-in: %+v, %v; want a session, the email being proved", res, err)
		}
	})
	t.Run("hosted", func(t *testing.T) {
		svc := newService(t)
		svc.mfa = heldFactor{code: "975310"}
		a, organization := member(t)
		svc.devicePolicy = rememberIn(organization)
		device, err := svc.CreateTrustedDevice(ctx, a.ID, organization, testUserAgent, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		other := dbtest.Organization(t)
		if res, err := svc.BeginMagicLinkSession(ctx, a.ID, organization, ip, testUserAgent, device, ""); err != nil || res.RawCookie == "" {
			t.Errorf("hosted link on the remembered device: %+v, %v; want the session cookie", res, err)
		}
		res, err := svc.BeginMagicLinkSession(ctx, a.ID, other, ip, testUserAgent, device, "")
		if err != nil || res.RawCookie != "" || !res.MFARequired {
			t.Fatalf("hosted link for another organization on the device: %+v, %v; want a challenge", res, err)
		}
		userID, _, cookie, err := svc.CompleteMFALoginSession(ctx, res.MFAToken, "975310", ip, testUserAgent)
		if err != nil || userID != a.ID || cookie == "" {
			t.Errorf("complete the hosted challenge: %s %q, %v", userID, cookie, err)
		}
	})
}
