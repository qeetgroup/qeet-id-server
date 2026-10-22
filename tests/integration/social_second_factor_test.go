//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestSocialSignInTakesTheSecondFactorDecision: a social sign-in
// issued its session on the provider's word alone — no challenge for a factor
// the account holds, no enrolment where the organisation requires one, no risk
// check — in the token flow, the hosted flow and the console's own. Each now
// takes the same decision as a password sign-in, and the session it completes
// records the factor it met.
func TestSocialSignInTakesTheSecondFactorDecision(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newFactorFixture(t, ctx)
	const ip, ua = "203.0.113.20", "browser"
	const returnTo = "https://app.example/oauth/authorize?client_id=rp"

	// providerFor configures a fake provider on the organisation that signs in
	// one fresh identity, and returns the social service using it.
	providerFor := func(t *testing.T, tenantID uuid.UUID) (*social.Service, string) {
		t.Helper()
		sub := uniqueSlug("sub")
		idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true,"name":"Social Person"}`,
			sub, sub+"@example.com"))
		t.Cleanup(idp.Close)
		provider := uniqueSlug("idp")
		if _, err := testPool.Exec(ctx, `
			INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
			VALUES ($1, $2, 'cid', 'csecret', $3)`, tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
			t.Fatal(err)
		}
		setSelfRegistration(t, ctx, tenantID, true)
		svc := social.NewService(testPool, f.auth, "http://app.local", egress.DevelopmentPolicy())
		svc.SetCipher(testEnvelope(t))
		svc.SetAllowedReturnOrigins("https://app.example")
		return svc, provider
	}
	// signIn runs the provider round trip and returns its callback result.
	signIn := func(t *testing.T, svc *social.Service, provider string, tenantID uuid.UUID, ret string) *social.CallbackResult {
		t.Helper()
		authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), "http://api.local/v1/social/"+provider+"/callback", ret)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(authURL)
		res, err := svc.CompleteCallback(ctx, provider, u.Query().Get("state"), "upstream-code", true)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("an account holding a factor is challenged for it, and the session records it", func(t *testing.T) {
		svc, provider := providerFor(t, f.tenantID)
		first, err := svc.ExchangeLogin(ctx, signIn(t, svc, provider, f.tenantID, "").Code, ip, ua)
		if err != nil || first.Pair == nil {
			t.Fatalf("first sign-in, no factor yet = %+v, %v; want a session", first, err)
		}
		secret := f.holdTOTP(t, ctx, first.Pair.UserID)

		again, err := svc.ExchangeLogin(ctx, signIn(t, svc, provider, f.tenantID, "").Code, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if again.Pair != nil || !again.MFARequired || again.MFAToken == "" {
			t.Fatalf("sign-in holding a factor = pair %v, mfa_required %v; want a challenge and no session", again.Pair != nil, again.MFARequired)
		}
		rr, c := f.complete(map[string]any{"mfa_token": again.MFAToken, "code": totpCodeAtStep(t, secret, 0)})
		if rr.Code != http.StatusOK || c.AccessToken == "" {
			t.Fatalf("completing the challenge = %d %s", rr.Code, rr.Body.String())
		}
		var factor, method string
		if err := testPool.QueryRow(ctx, `
			SELECT COALESCE(s.second_factor, ''), e.metadata->>'method'
			FROM auth.sessions s JOIN audit.events e ON e.resource_id = s.id AND e.action = 'auth.login_succeeded'
			WHERE s.user_id = $1 ORDER BY s.created_at DESC LIMIT 1`, first.Pair.UserID).Scan(&factor, &method); err != nil {
			t.Fatal(err)
		}
		if factor != "mfa" || method != "social_mfa" {
			t.Fatalf("completed session second_factor=%q method=%q; want mfa and social_mfa", factor, method)
		}
	})

	t.Run("an organisation that requires a factor sends a member without one into enrolment", func(t *testing.T) {
		org := createTenant(t, ctx, uniqueSlug("social-mfa"))
		requireMFA(t, ctx, org, "required", 0, nil)
		svc, provider := providerFor(t, org)
		res, err := svc.ExchangeLogin(ctx, signIn(t, svc, provider, org, "").Code, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if res.Pair != nil || !res.MFARequired || !res.EnrollmentRequired {
			t.Fatalf("result = pair %v, mfa_required %v, enrollment_required %v; want the enrolment challenge", res.Pair != nil, res.MFARequired, res.EnrollmentRequired)
		}
	})

	t.Run("the hosted flow hands the challenge to the hosted login instead of setting the cookie", func(t *testing.T) {
		svc, provider := providerFor(t, f.tenantID)
		first, err := svc.ExchangeLogin(ctx, signIn(t, svc, provider, f.tenantID, "").Code, ip, ua)
		if err != nil || first.Pair == nil {
			t.Fatalf("first sign-in = %+v, %v", first, err)
		}
		h := &social.Handler{Service: svc, LoginBaseURL: "http://login.test"}
		router := chi.NewRouter()
		router.Route("/v1", h.MountPublic)
		callback := func(t *testing.T) *httptest.ResponseRecorder {
			t.Helper()
			authURL, err := svc.BeginLogin(ctx, provider, f.tenantID.String(), "http://api.local/v1/social/"+provider+"/callback", returnTo)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(authURL)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, socialCallback(provider, u.Query().Get("state")))
			return rr
		}
		cookieSet := func(rr *httptest.ResponseRecorder) bool {
			for _, c := range rr.Result().Cookies() {
				if c.Name == auth.LoginSessionCookie && c.Value != "" {
					return true
				}
			}
			return false
		}

		rr := callback(t)
		if loc := rr.Header().Get("Location"); rr.Code != http.StatusFound || loc != returnTo || !cookieSet(rr) {
			t.Fatalf("no factor held = %d %q cookie=%v; want the cookie and a return to the application", rr.Code, loc, cookieSet(rr))
		}

		f.holdTOTP(t, ctx, first.Pair.UserID)
		rr = callback(t)
		loc, _ := url.Parse(rr.Header().Get("Location"))
		frag, _ := url.ParseQuery(loc.Fragment)
		if rr.Code != http.StatusFound || loc.Host != "login.test" || loc.Path != "/login" || loc.Query().Get("return_to") != returnTo {
			t.Fatalf("holding a factor = %d %s; want the hosted login, keeping return_to", rr.Code, loc)
		}
		if frag.Get("mfa_token") == "" || !strings.Contains(frag.Get("methods"), "totp") || loc.Query().Get("mfa_token") != "" {
			t.Fatalf("challenge = fragment %q query %q; want mfa_token and methods in the fragment only", loc.Fragment, loc.RawQuery)
		}
		// The factors travel with it, as a password sign-in's challenge lists
		// them, so the hosted login can offer each one.
		var factors []auth.LoginFactor
		if err := json.Unmarshal([]byte(frag.Get("factors")), &factors); err != nil || len(factors) == 0 || factors[0].Type != "totp" {
			t.Fatalf("challenge factors = %q (%v); want the factors the account holds", frag.Get("factors"), err)
		}
		if cookieSet(rr) {
			t.Fatal("the hosted sign-in cookie was set before the factor was met")
		}
	})

	t.Run("the console's own social sign-in is challenged the same way", func(t *testing.T) {
		svc, provider := providerFor(t, f.tenantID)
		first, err := svc.ExchangeLogin(ctx, signIn(t, svc, provider, f.tenantID, "").Code, ip, ua)
		if err != nil || first.Pair == nil {
			t.Fatalf("first sign-in = %+v, %v", first, err)
		}
		f.holdTOTP(t, ctx, first.Pair.UserID)
		raw := uniqueSlug("platform-code")
		if _, err := testPool.Exec(ctx, `INSERT INTO auth.platform_social_codes (code_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			codes.Hash(raw), first.Pair.UserID, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		res, err := svc.ExchangePlatformLogin(ctx, raw, ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		if res.Pair != nil || !res.MFARequired {
			t.Fatalf("console social sign-in holding a factor = pair %v, mfa_required %v; want a challenge", res.Pair != nil, res.MFARequired)
		}
	})
}
