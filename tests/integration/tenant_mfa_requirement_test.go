//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestOrganisationMFARequirementAppliesWhereverItIsEntered (QTID-800): an
// organisation's second-factor requirement was read only for the account's
// own organisation, at sign-in. Anyone at home elsewhere signed in there with a
// password and then switched in, accepted the organisation's invitation, or
// signed in to one of its applications, and got a session or a code with no
// factor asked for. Each of those now asks first, carries a factor already met,
// and leaves the grace period and administrators-only mode as at sign-in.
func TestOrganisationMFARequirementAppliesWhereverItIsEntered(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx) // home organisation: no requirement
	orgB := createTenant(t, ctx, uniqueSlug("requires-mfa"))
	requireMFA(t, ctx, orgB, "required", 0, nil)
	const ip, ua = "203.0.113.9", "browser"

	// someone is at home in the fixture's organisation and a member of org.
	someone := func(t *testing.T, org uuid.UUID, withFactor bool) (uuid.UUID, string) {
		t.Helper()
		id, email := f.member(t, ctx)
		addTenantMembership(t, ctx, id, org)
		if withFactor {
			f.holdTOTP(t, ctx, id)
		}
		return id, email
	}
	// homeSession is a session at home opened by a sign-in of method.
	homeSession := func(t *testing.T, id uuid.UUID, method string) uuid.UUID {
		t.Helper()
		pair, err := f.auth.IssuePair(ctx, id, f.tenantID, ip, ua, method)
		if err != nil {
			t.Fatal(err)
		}
		return pair.SessionID
	}
	switchTo := func(id, from, org uuid.UUID) (*auth.TokenPair, error) {
		return f.auth.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: id, FromSessionID: from, TenantID: org, IP: ip, UserAgent: ua})
	}
	factorOf := func(t *testing.T, sessionID uuid.UUID) string {
		t.Helper()
		var factor string
		if err := testPool.QueryRow(ctx, `SELECT COALESCE(second_factor, '') FROM auth.sessions WHERE id = $1`, sessionID).Scan(&factor); err != nil {
			t.Fatal(err)
		}
		return factor
	}
	stepUp := func(t *testing.T, sessionID, id uuid.UUID, ago time.Duration) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `
			INSERT INTO auth.mfa_verifications (session_id, user_id, method, verified_at)
			VALUES ($1, $2, 'totp', NOW() - make_interval(secs => $3))`, sessionID, id, ago.Seconds()); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("switching in after a password-only sign-in asks for the factor, and changes nothing", func(t *testing.T) {
		id, _ := someone(t, orgB, true)
		from := homeSession(t, id, "password")
		if _, err := switchTo(id, from, orgB); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Fatalf("switch = %v, want step_up_required", err)
		}
		var revoked bool
		if err := testPool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE id = $1`, from).Scan(&revoked); err != nil || revoked {
			t.Fatalf("the session switched from ended (revoked=%v, err=%v)", revoked, err)
		}
	})

	t.Run("a sign-in that met a factor switches in without a second challenge, and the session carries it", func(t *testing.T) {
		id, _ := someone(t, orgB, true)
		pair, err := switchTo(id, homeSession(t, id, "password_mfa"), orgB)
		if err != nil {
			t.Fatalf("switch after a met challenge: %v", err)
		}
		if got := factorOf(t, pair.SessionID); got != "mfa" {
			t.Fatalf("new session second_factor = %q, want mfa", got)
		}
		addTenantMembership(t, ctx, id, f.tenantID)
		home, err := switchTo(id, pair.SessionID, f.tenantID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := switchTo(id, home.SessionID, orgB); err != nil {
			t.Fatalf("switching back in again: %v", err)
		}
	})

	t.Run("a fresh step-up of the session switched from counts; a stale one doesn't", func(t *testing.T) {
		id, _ := someone(t, orgB, true)
		stale := homeSession(t, id, "password")
		stepUp(t, stale, id, 10*time.Minute)
		if _, err := switchTo(id, stale, orgB); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Fatalf("switch with a stale step-up = %v, want step_up_required", err)
		}
		fresh := homeSession(t, id, "password")
		stepUp(t, fresh, id, 0)
		pair, err := switchTo(id, fresh, orgB)
		if err != nil {
			t.Fatalf("switch with a fresh step-up: %v", err)
		}
		if got := factorOf(t, pair.SessionID); got != "step_up" {
			t.Fatalf("new session second_factor = %q, want step_up", got)
		}
	})

	t.Run("a member with no factor must set one up, unless the grace period still runs for them", func(t *testing.T) {
		id, _ := someone(t, orgB, false)
		if _, err := switchTo(id, homeSession(t, id, "password"), orgB); !errors.Is(err, errs.ErrMFAEnrollmentRequired) {
			t.Fatalf("switch = %v, want mfa.enrollment_required", err)
		}

		orgC := createTenant(t, ctx, uniqueSlug("grace"))
		since := time.Now().Add(-time.Hour)
		requireMFA(t, ctx, orgC, "required", 7, &since)
		existing, _ := someone(t, orgC, false)
		if _, err := testPool.Exec(ctx, `UPDATE rbac.user_roles SET granted_at = NOW() - INTERVAL '2 hours'
			WHERE user_id = $1 AND tenant_id = $2`, existing, orgC); err != nil {
			t.Fatal(err)
		}
		if _, err := switchTo(existing, homeSession(t, existing, "password"), orgC); err != nil {
			t.Fatalf("a member from before the requirement, in its grace period: %v", err)
		}
		joinedLater, _ := someone(t, orgC, false)
		if _, err := switchTo(joinedLater, homeSession(t, joinedLater, "password"), orgC); !errors.Is(err, errs.ErrMFAEnrollmentRequired) {
			t.Fatalf("a member who joined after the requirement = %v, want mfa.enrollment_required", err)
		}
	})

	t.Run("administrators-only mode asks the organisation's administrators only", func(t *testing.T) {
		orgD := createTenant(t, ctx, uniqueSlug("admins-mfa"))
		requireMFA(t, ctx, orgD, "admin_only", 0, nil)
		member, _ := someone(t, orgD, true)
		if _, err := switchTo(member, homeSession(t, member, "password"), orgD); err != nil {
			t.Fatalf("a member who isn't an administrator: %v", err)
		}
		admin, _ := someone(t, orgD, true)
		if _, err := testPool.Exec(ctx, `INSERT INTO rbac.user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`,
			admin, orgD, writeRole(t, ctx, orgD)); err != nil {
			t.Fatal(err)
		}
		if _, err := switchTo(admin, homeSession(t, admin, "password"), orgD); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Fatalf("an administrator = %v, want step_up_required", err)
		}
	})

	t.Run("accepting an invitation while signed in is gated the same way", func(t *testing.T) {
		id, _ := someone(t, orgB, true)
		if _, err := f.auth.EnterInvitedTenant(ctx, id, orgB, homeSession(t, id, "password"), ip, ua); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Fatalf("enter after a password-only sign-in = %v, want step_up_required", err)
		}
		if _, err := f.auth.EnterInvitedTenant(ctx, id, orgB, uuid.Nil, ip, ua); !errors.Is(err, errs.ErrStepUpRequired) {
			t.Fatalf("enter with no session = %v, want step_up_required", err)
		}
		pair, err := f.auth.EnterInvitedTenant(ctx, id, orgB, homeSession(t, id, "password_mfa"), ip, ua)
		if err != nil {
			t.Fatalf("enter after a met challenge: %v", err)
		}
		if got := factorOf(t, pair.SessionID); got != "mfa" {
			t.Fatalf("new session second_factor = %q, want mfa", got)
		}
	})

	t.Run("an account an invitation creates sets up its factor before any session", func(t *testing.T) {
		id := createTenantUser(t, ctx, orgB, uniqueSlug("invited")+"@example.com")
		res, err := f.auth.SignInInvitedAccount(ctx, id, orgB, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if res.Pair != nil || !res.MFARequired || !res.EnrollmentRequired {
			t.Fatalf("result = pair %v, mfa_required %v, enrollment_required %v; want the enrolment challenge", res.Pair != nil, res.MFARequired, res.EnrollmentRequired)
		}
	})

	// The hosted sign-in and authorize, for an application of org B.
	svc := oidc.NewService(testPool, mustIssuer())
	redirect := "https://app.example/cb"
	client, _ := registerOIDCClient(t, ctx, svc, orgB, redirect)
	h := &oidc.Handler{Service: svc, Sessions: f.auth, LoginBaseURL: "http://login.test"}
	router := chi.NewRouter()
	router.Route("/v1", h.MountBrowser)
	authorize := func(cookie string, extra url.Values) *url.URL {
		q := url.Values{"client_id": {client.ClientID}, "redirect_uri": {redirect}, "scope": {"openid"},
			"state": {"s1"}, "response_type": {"code"}, "nonce": {testNonce},
			"code_challenge": {testChallenge}, "code_challenge_method": {"S256"}}
		for k, v := range extra {
			q[k] = v
		}
		return get(router, "/v1/oauth/authorize?"+q.Encode(), cookie)
	}
	consented := func(t *testing.T, withFactor bool) (uuid.UUID, string) {
		t.Helper()
		id, email := someone(t, orgB, withFactor)
		if err := svc.GrantConsent(ctx, id, client.ClientID, []string{"openid"}); err != nil {
			t.Fatal(err)
		}
		return id, email
	}

	t.Run("a hosted sign-in for the application asks for its organisation's factor", func(t *testing.T) {
		_, email := consented(t, false)
		without, err := f.auth.BeginLoginSession(ctx, auth.SignInAttempt{Email: email, Password: factorPassword, IP: ip}, ua, "", "")
		if err != nil || without.RawCookie == "" {
			t.Fatalf("sign-in serving no application = %+v, %v; want a session (home asks for nothing)", without, err)
		}
		for_, err := f.auth.BeginLoginSession(ctx, auth.SignInAttempt{Email: email, Password: factorPassword, IP: ip, ClientID: client.ClientID}, ua, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if for_.RawCookie != "" || !for_.MFAChallenge.MFARequired || !for_.MFAChallenge.EnrollmentRequired {
			t.Fatalf("sign-in for org B's application = %+v; want the enrolment challenge and no session", for_)
		}
	})

	t.Run("authorize sends a sign-in without the factor to sign in again, once, then refuses", func(t *testing.T) {
		id, _ := consented(t, true)
		cookie, err := f.auth.CreateLoginSession(ctx, id, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		loc := authorize(cookie, nil)
		if loc == nil || loc.Host != "login.test" || loc.Query().Get("prompt") != "login" {
			t.Fatalf("authorize = %v, want the hosted login asked to sign in again", loc)
		}
		if loc := authorize(cookie, url.Values{"prompt": {"none"}}); loc == nil || loc.Query().Get("error") != "interaction_required" {
			t.Fatalf("prompt=none = %v, want interaction_required", loc)
		}
		// Back from that sign-in, still without the factor: refused, no loop.
		after := url.Values{"login_after": {strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)}}
		if loc := authorize(cookie, after); loc == nil || loc.Host != "app.example" || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
			t.Fatalf("after signing in again = %v, want access_denied at the application", loc)
		}
	})

	t.Run("a sign-in that met the factor gets its code", func(t *testing.T) {
		id, _ := consented(t, true)
		cookie, err := f.auth.CreatePasskeyLoginSession(ctx, id, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if loc := authorize(cookie, nil); loc == nil || loc.Host != "app.example" || loc.Query().Get("code") == "" {
			t.Fatalf("authorize after a passkey sign-in = %v, want a code", loc)
		}
	})

	t.Run("approving a device for the application asks for the factor too", func(t *testing.T) {
		id, _ := consented(t, true)
		cookie, err := f.auth.CreateLoginSession(ctx, id, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `UPDATE auth.oidc_clients SET grant_types = array_append(grant_types, 'urn:ietf:params:oauth:grant-type:device_code')
			WHERE client_id = $1`, client.ClientID); err != nil {
			t.Fatal(err)
		}
		_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"user_code": userCode, "approve": true})
		req := httptest.NewRequest(http.MethodPost, "/v1/oauth/device/decision", bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("approve = %d %s, want 403 step_up_required", rr.Code, rr.Body.String())
		}
	})
}
