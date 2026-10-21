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
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestSuspendedAccountsCannotSignInAnyWay: password and magic-link
// sign-in refused a suspended account, but a passkey or a social provider
// signed it straight back in. Every sign-in now ends in the one issuing step,
// which refuses an account that isn't active (or invited) once the credential
// is proved, with the password path's answer, and audits the refusal; a
// social sign-in gets no one-time code to begin with.
func TestSuspendedAccountsCannotSignInAnyWay(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	const ip, ua = "203.0.113.30", "browser"
	suspend := func(t *testing.T, id uuid.UUID) {
		t.Helper()
		if _, err := testPool.Exec(ctx, `UPDATE "user".users SET status = 'suspended' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	refusalAudited := func(t *testing.T, id uuid.UUID) {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events
			WHERE resource_id = $1 AND action = 'auth.sign_in_refused' AND metadata->>'reason' = 'account_inactive'
			  AND metadata->>'status' = 'suspended'`, id).Scan(&n); err != nil || n == 0 {
			t.Fatalf("no auth.sign_in_refused account_inactive audit (n=%d, err=%v)", n, err)
		}
	}

	t.Run("a valid passkey assertion signs in no suspended account, token or hosted", func(t *testing.T) {
		svc := newPasskeySvc(t)
		rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
		authenticator := virtualwebauthn.NewAuthenticator()
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		email := uniqueSlug("pk-suspended") + "@example.com"
		sid, creation, err := svc.BeginSignup(ctx, email, "Ada")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(creation)
		aopts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		_, userID, err := svc.FinishSignup(ctx, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *aopts)), "Laptop", ip, ua)
		if err != nil {
			t.Fatal(err)
		}
		authenticator.AddCredential(cred)
		suspend(t, userID)

		loginSID, assertion, err := svc.BeginLogin(ctx, email)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ = json.Marshal(assertion)
		asOpts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		pair, err := svc.FinishLogin(ctx, loginSID, json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *asOpts)), ip, ua)
		if !errors.Is(err, errs.ErrAuthAccountInactive) || pair != nil {
			t.Fatalf("passkey sign-in of a suspended account = %v, %v; want auth.account_inactive and no pair", pair != nil, err)
		}
		if cookie, err := svc.StartLoginSession(ctx, userID, ip, ua); !errors.Is(err, errs.ErrAuthAccountInactive) || cookie != "" {
			t.Fatalf("hosted passkey sign-in of a suspended account = %q, %v; want auth.account_inactive and no cookie", cookie, err)
		}
		refusalAudited(t, userID)
	})

	// The social provider of an organisation, signing in one fresh identity.
	authSvc, _ := newAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("social-suspended"))
	setSelfRegistration(t, ctx, tenantID, true)
	providerFor := func(t *testing.T) (*social.Service, string) {
		t.Helper()
		sub := uniqueSlug("sub")
		idp := fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":true}`, sub, sub+"@example.com"))
		t.Cleanup(idp.Close)
		provider := uniqueSlug("idp")
		if _, err := testPool.Exec(ctx, `
			INSERT INTO tenant.social_providers (tenant_id, provider, client_id, client_secret, discovery_url)
			VALUES ($1, $2, 'cid', 'csecret', $3)`, tenantID, provider, idp.URL+"/.well-known/openid-configuration"); err != nil {
			t.Fatal(err)
		}
		svc := social.NewService(testPool, authSvc, "http://app.local", egress.DevelopmentPolicy())
		svc.SetCipher(testEnvelope(t))
		svc.SetAllowedReturnOrigins("https://app.example")
		return svc, provider
	}
	begin := func(t *testing.T, svc *social.Service, provider, returnTo string) string {
		t.Helper()
		authURL, err := svc.BeginLogin(ctx, provider, tenantID.String(), "http://api.local/v1/social/"+provider+"/callback", returnTo)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(authURL)
		return u.Query().Get("state")
	}

	t.Run("an organisation's social sign-in gets no code, and the hosted one no cookie", func(t *testing.T) {
		svc, provider := providerFor(t)
		first, err := svc.CompleteCallback(ctx, provider, begin(t, svc, provider, ""), "upstream-code")
		if err != nil || first.Code == "" {
			t.Fatalf("active account = %+v, %v; want a code", first, err)
		}
		suspend(t, first.UserID)
		if res, err := svc.CompleteCallback(ctx, provider, begin(t, svc, provider, ""), "upstream-code"); !errors.Is(err, errs.ErrAuthAccountInactive) || (res != nil && res.Code != "") {
			t.Fatalf("suspended account = %+v, %v; want auth.account_inactive and no code", res, err)
		}
		refusalAudited(t, first.UserID)

		h := &social.Handler{Service: svc, LoginBaseURL: "http://login.test"}
		router := chi.NewRouter()
		router.Route("/v1", h.MountPublic)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/social/"+provider+"/callback?"+url.Values{
			"state": {begin(t, svc, provider, "https://app.example/oauth/authorize?client_id=rp")}, "code": {"upstream-code"}}.Encode(), nil))
		loc, _ := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || loc.Host != "login.test" || loc.Query().Get("error") != "account_inactive" {
			t.Fatalf("hosted callback = %d %s; want the hosted login with error=account_inactive", rr.Code, loc)
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == auth.LoginSessionCookie && c.Value != "" {
				t.Fatal("a hosted sign-in cookie was set for a suspended account")
			}
		}
	})

	t.Run("a suspended console account is refused a platform social sign-in", func(t *testing.T) {
		svc, provider := providerFor(t)
		first, err := svc.CompleteCallback(ctx, provider, begin(t, svc, provider, ""), "upstream-code")
		if err != nil {
			t.Fatal(err)
		}
		suspend(t, first.UserID)
		raw := uniqueSlug("platform-code")
		if _, err := testPool.Exec(ctx, `INSERT INTO auth.platform_social_codes (code_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			codes.Hash(raw), first.UserID, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if res, err := svc.ExchangePlatformLogin(ctx, raw, ip, ua); !errors.Is(err, errs.ErrAuthAccountInactive) || res != nil {
			t.Fatalf("platform exchange = %+v, %v; want auth.account_inactive", res, err)
		}
	})
}
