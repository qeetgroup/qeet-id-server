//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/policy"
	"github.com/qeetgroup/qeet-id-server/internal/access/risk/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Addresses the tests sign in from. httptest requests come from 192.0.2.1.
const (
	deniedAddr  = "192.0.2.10"
	allowedAddr = "198.51.100.7"
)

// addressRules turns an organisation's address rules on or off and adds rules
// to it, returning the rules' ids.
func addressRules(t *testing.T, ctx context.Context, tenantID uuid.UUID, on bool, rules ...[2]string) []uuid.UUID {
	t.Helper()
	svc := ipallow.NewService(testPool)
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	if err := svc.SetEnabled(ctx, tx, tenantID, on); err != nil {
		t.Fatalf("set enabled: %v", err)
	}
	var ids []uuid.UUID
	for _, r := range rules {
		rule, err := svc.AddRule(ctx, tx, tenantID, r[0], "test", r[1])
		if err != nil {
			t.Fatalf("add rule %v: %v", r, err)
		}
		ids = append(ids, rule.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return ids
}

// TestAddressRulesDecideEverySignIn pins the organisation's address rules to
// every way of signing in to it: with the rules on, an address they refuse
// gets no session by any method, no application authorization, no device
// approval and no device tokens, and a session already open stops renewing
// from it. Each refusal is recorded with the rule responsible. With the rules
// off, nothing changes.
func TestAddressRulesDecideEverySignIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()

	// Google denies 192.0.2.0/24, where the tests' HTTP requests come from.
	google := createTenant(t, ctx, uniqueSlug("addr-deny"))
	denyRule := addressRules(t, ctx, google, true, [2]string{"192.0.2.0/24", "deny"})[0]
	member := func(t *testing.T, tenantID uuid.UUID) uuid.UUID {
		t.Helper()
		id := createUserInTenant(t, ctx, tenantID)
		addTenantMembership(t, ctx, id, tenantID)
		return id
	}
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			t.Fatalf("%s: err = %v, want %v", what, err, errs.ErrAuthAddressNotAllowed)
		}
	}
	sessionsIn := func(t *testing.T, userID, tenantID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		return n
	}

	t.Run("password sign-in over the API is refused with 403", func(t *testing.T) {
		email := uniqueSlug("addr") + "@example.com"
		uma := createTenantUser(t, ctx, google, email)
		addTenantMembership(t, ctx, uma, google)
		hash, err := password.Hash(factorPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx,
			`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`, uma, hash); err != nil {
			t.Fatal(err)
		}
		r := chi.NewRouter()
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).Mount(r)
		body, _ := json.Marshal(map[string]string{"email": email, "password": factorPassword})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		var out struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		if rr.Code != http.StatusForbidden || out.Error.Code != errs.CodeAuthAddressNotAllowed {
			t.Fatalf("login: %d %s; want 403 %s", rr.Code, rr.Body.String(), errs.CodeAuthAddressNotAllowed)
		}
		if strings.Contains(rr.Body.String(), "192.0.2.0/24") || strings.Contains(rr.Body.String(), denyRule.String()) {
			t.Fatalf("the refusal shows the rule: %s", rr.Body.String())
		}
		if sessionsIn(t, uma, google) != 0 {
			t.Fatal("a refused password sign-in left a session")
		}
	})

	t.Run("every other sign-in method is refused", func(t *testing.T) {
		uma := member(t, google)
		for _, method := range []string{"passkey", "magic_link", "social", "saml", "ldap", "invite_accept", "tenant_create"} {
			_, err := authSvc.IssuePair(ctx, uma, google, deniedAddr, "browser", method)
			refused(t, method, err)
		}
		if sessionsIn(t, uma, google) != 0 {
			t.Fatal("a refused sign-in left a session")
		}
	})

	t.Run("switching into the organisation is refused", func(t *testing.T) {
		home := createTenant(t, ctx, uniqueSlug("addr-home"))
		uma := member(t, home)
		addTenantMembership(t, ctx, uma, google)
		pair, err := authSvc.IssuePair(ctx, uma, home, deniedAddr, "browser", "password")
		if err != nil {
			t.Fatalf("sign in at home: %v", err)
		}
		_, err = authSvc.SwitchTenant(ctx, auth.SwitchTenantInput{
			UserID: uma, FromSessionID: pair.SessionID, TenantID: google, IP: deniedAddr, UserAgent: "browser",
		})
		refused(t, "switch", err)
	})

	t.Run("an allowed address signs in as before", func(t *testing.T) {
		if _, err := authSvc.IssuePair(ctx, member(t, google), google, allowedAddr, "browser", "password"); err != nil {
			t.Fatalf("sign in from an allowed address: %v", err)
		}
	})

	t.Run("a session stops renewing from a newly blocked address, and renews again from an allowed one", func(t *testing.T) {
		pair, err := authSvc.IssuePair(ctx, member(t, google), google, allowedAddr, "browser", "password")
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		_, err = authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken, IP: deniedAddr})
		refused(t, "refresh", err)
		if _, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken, IP: allowedAddr}); err != nil {
			t.Fatalf("refresh from an allowed address after the refusal: %v", err)
		}
	})

	t.Run("a sign-in whose address can't be read is refused", func(t *testing.T) {
		_, err := authSvc.IssuePair(ctx, member(t, google), google, "", "browser", "password")
		refused(t, "no address", err)
	})

	t.Run("an application can't authorize or take a device sign-in from a refused address", func(t *testing.T) {
		svc := oidc.NewService(testPool, mustIssuer())
		svc.SetAddressPolicy(ipallow.NewService(testPool))
		tx, err := testPool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		redirect := "https://app.example/cb"
		client, _, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{
			TenantID: google, Name: "RP", Type: "confidential", RedirectURIs: []string{redirect},
			GrantTypes: []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		})
		if err != nil {
			t.Fatalf("register client: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
		uma := member(t, google)

		authorize := func(addr string) error {
			_, _, err := svc.AuthorizeInLoginSession(ctx, uuid.Nil, uma, client.ClientID, redirect, []string{"openid"},
				"n-0S6_WzA2Mj", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256", addr)
			return err
		}
		refused(t, "authorize", authorize(deniedAddr))
		if err := authorize(allowedAddr); err != nil {
			t.Fatalf("authorize from an allowed address: %v", err)
		}

		_, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		refused(t, "device approval", svc.DecideDevice(ctx, uma, userCode, true, deniedAddr))

		device, userCode, _, err := svc.DeviceAuthorize(ctx, client.ClientID, []string{"openid"})
		if err != nil {
			t.Fatalf("device authorize: %v", err)
		}
		if err := svc.DecideDevice(ctx, uma, userCode, true, allowedAddr); err != nil {
			t.Fatalf("approve from an allowed address: %v", err)
		}
		_, err = svc.DeviceToken(ctx, client.ClientID, device, deniedAddr)
		if err == nil || !strings.Contains(err.Error(), "address_not_allowed") {
			t.Fatalf("device tokens to a refused address: err = %v, want access_denied address_not_allowed", err)
		}
	})

	t.Run("each refusal is recorded with the rule responsible", func(t *testing.T) {
		var n int
		if err := testPool.QueryRow(ctx, `
			SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'auth.address_refused' AND resource_id = $2
			  AND metadata->>'rule_id' = $2::text AND metadata->>'reason' = 'deny_rule'
			  AND metadata->>'path' = 'refresh' AND host(ip) = $3`, google, denyRule, deniedAddr).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if n != 1 {
			t.Fatalf("refused renewals recorded with the deny rule = %d, want 1", n)
		}
		if err := testPool.QueryRow(ctx, `
			SELECT count(*) FROM audit.events
			WHERE tenant_id = $1 AND action = 'auth.address_refused' AND metadata->>'reason' = 'address_unknown'`,
			google).Scan(&n); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if n != 1 {
			t.Fatalf("refusals of an unreadable address recorded = %d, want 1", n)
		}
	})

	t.Run("outside every allow rule is refused", func(t *testing.T) {
		microsoft := createTenant(t, ctx, uniqueSlug("addr-allow"))
		addressRules(t, ctx, microsoft, true, [2]string{"203.0.113.0/24", "allow"})
		uma := member(t, microsoft)
		_, err := authSvc.IssuePair(ctx, uma, microsoft, allowedAddr, "browser", "password")
		refused(t, "outside the allow rules", err)
		if _, err := authSvc.IssuePair(ctx, uma, microsoft, "203.0.113.9", "browser", "password"); err != nil {
			t.Fatalf("sign in from inside the allow rule: %v", err)
		}
	})

	t.Run("with the rules off, nothing changes", func(t *testing.T) {
		apple := createTenant(t, ctx, uniqueSlug("addr-off"))
		addressRules(t, ctx, apple, false, [2]string{"192.0.2.0/24", "deny"})
		if _, err := authSvc.IssuePair(ctx, member(t, apple), apple, deniedAddr, "browser", "password"); err != nil {
			t.Fatalf("sign in with the rules off: %v", err)
		}
	})
}

// TestSecurityPolicyHasNoIPLists pins the security policy's retired IP lists:
// it no longer reports them, a console that still sends them empty saves as
// before, and entries are refused, pointing at address rules.
func TestSecurityPolicyHasNoIPLists(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("policy-lists"))
	r := chi.NewRouter()
	(&policy.Handler{Repo: policy.NewRepository(testPool)}).Mount(r)
	do := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/tenants/"+tenantID.String()+"/policy", strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}
	const rest = `"password_min_length":8,"password_complexity":"standard","session_max_age":"720h",` +
		`"session_idle_timeout":"24h","session_limit_action":"evict_oldest","mfa_enforcement":"optional","step_up_window":"5m"`

	if rr := do(http.MethodPut, `{"ip_allowlist":[],"ip_denylist":[],`+rest+`}`); rr.Code != http.StatusOK {
		t.Fatalf("save with empty lists: %d %s", rr.Code, rr.Body.String())
	}
	for _, field := range []string{"ip_allowlist", "ip_denylist"} {
		rr := do(http.MethodPut, `{"`+field+`":["10.0.0.0/8"],`+rest+`}`)
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), `"retired"`) {
			t.Fatalf("save with %s entries: %d %s; want 422 retired", field, rr.Code, rr.Body.String())
		}
	}
	rr := do(http.MethodGet, "")
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "ip_allowlist") || strings.Contains(rr.Body.String(), "ip_denylist") {
		t.Fatalf("read policy: %d %s; want no IP lists", rr.Code, rr.Body.String())
	}
}

// TestTheHostedLoginRefusesAnAddressAtSignIn pins the address rules to the
// hosted login, where the sign-in opens a session for the browser rather than
// for an organisation: the organisation of the application being signed in to
// (or of the magic link, or being joined) refuses there, so the person is told
// on the hosted login, not sent to the application with access_denied. The
// password answer is the same whether the password is right or wrong.
func TestTheHostedLoginRefusesAnAddressAtSignIn(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, true)
	addressRules(t, ctx, f.tenantID, true, [2]string{"192.0.2.0/24", "deny"})
	authSvc, _ := newAuth()
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, errs.ErrAuthAddressNotAllowed) {
			t.Fatalf("%s: err = %v, want %v", what, err, errs.ErrAuthAddressNotAllowed)
		}
	}

	t.Run("a social sign-in goes back to the hosted login with the address error", func(t *testing.T) {
		h := &social.Handler{Service: f.svc, LoginBaseURL: "http://login.test"}
		r := chi.NewRouter()
		r.Route("/v1", h.MountPublic)
		req := httptest.NewRequest(http.MethodGet, "/v1/social/"+f.provider+"/callback?state="+url.QueryEscape(f.begin(t, ctx))+"&code=upstream-code", nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		loc, err := url.Parse(rr.Header().Get("Location"))
		if rr.Code != http.StatusFound || err != nil || loc.Host != "login.test" || loc.Path != "/login" ||
			loc.Query().Get("error") != "address_not_allowed" || loc.Query().Get("return_to") != closedRegReturnTo {
			t.Fatalf("callback = %d %q, want the hosted login with error=address_not_allowed and the return_to", rr.Code, rr.Header().Get("Location"))
		}
		if strings.Contains(rr.Header().Get("Set-Cookie"), auth.LoginSessionCookie) {
			t.Fatal("a refused social sign-in opened a hosted-login session")
		}
	})

	t.Run("a password sign-in for the organisation's application is refused, right password or wrong", func(t *testing.T) {
		email := uniqueSlug("hosted") + "@example.com"
		uma := createTenantUser(t, ctx, f.tenantID, email)
		addTenantMembership(t, ctx, uma, f.tenantID)
		hash, err := password.Hash(factorPassword)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx,
			`INSERT INTO auth.password_credentials (user_id, password_hash) VALUES ($1, $2)`, uma, hash); err != nil {
			t.Fatal(err)
		}
		svc := oidc.NewService(testPool, mustIssuer())
		client, _ := registerOIDCClient(t, ctx, svc, f.tenantID, "https://app.example/cb")
		r := chi.NewRouter()
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).Mount(r)
		signIn := func(pw, from string) *httptest.ResponseRecorder {
			body, _ := json.Marshal(map[string]string{"email": email, "password": pw, "client_id": client.ClientID})
			req := httptest.NewRequest(http.MethodPost, "/auth/session", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = from + ":1234"
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			return rr
		}
		for _, pw := range []string{factorPassword, "not-the-password"} {
			rr := signIn(pw, deniedAddr)
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), errs.CodeAuthAddressNotAllowed) {
				t.Fatalf("hosted sign-in: %d %s; want 403 %s", rr.Code, rr.Body.String(), errs.CodeAuthAddressNotAllowed)
			}
			if strings.Contains(rr.Header().Get("Set-Cookie"), auth.LoginSessionCookie) {
				t.Fatal("a refused hosted sign-in opened a hosted-login session")
			}
		}
		if rr := signIn(factorPassword, allowedAddr); rr.Code != http.StatusOK {
			t.Fatalf("hosted sign-in from an allowed address: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("a magic link for the organisation is refused", func(t *testing.T) {
		uma := createUserInTenant(t, ctx, f.tenantID)
		_, err := authSvc.BeginMagicLinkSession(ctx, uma, f.tenantID, deniedAddr, "browser", "", "")
		refused(t, "magic link", err)
	})

	t.Run("nobody joins the organisation from a refused address", func(t *testing.T) {
		email := uniqueSlug("joiner") + "@example.com"
		_, _, err := authSvc.RegisterInTenant(ctx, f.tenantID, email, "Kx7mQ2vLp9Wz!", "", deniedAddr, "browser")
		refused(t, "sign-up", err)
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM "user".users WHERE email = $1`, email).Scan(&n); err != nil || n != 0 {
			t.Fatalf("a refused sign-up created %d account(s) (%v)", n, err)
		}
	})
}

// TestAddressRulesNeverLockOutTheAdminChangingThem pins the guard on enforced
// rules: a change that would refuse the address it comes from (switching
// enforcement on, adding a deny rule, removing the allow rule that covers it)
// is refused, and nothing changes; switching enforcement off always works.
func TestAddressRulesNeverLockOutTheAdminChangingThem(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("addr-guard"))
	admin := createUserInTenant(t, ctx, tenantID)
	addTenantMembership(t, ctx, admin, tenantID)
	r := chi.NewRouter()
	r.Use(withPrincipal(admin, tenantID))
	(&ipallow.Handler{Service: ipallow.NewService(testPool)}).Mount(r)
	// httptest requests come from 192.0.2.1.
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/tenants/"+tenantID.String()+"/ip-rules"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr
	}
	lockedOut := func(t *testing.T, what string, rr *httptest.ResponseRecorder) {
		t.Helper()
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), errs.CodeRiskRulesLockOutCaller) {
			t.Fatalf("%s: %d %s; want 409 %s", what, rr.Code, rr.Body.String(), errs.CodeRiskRulesLockOutCaller)
		}
	}
	state := func(t *testing.T) (bool, []ipallow.Rule) {
		t.Helper()
		svc := ipallow.NewService(testPool)
		on, err := svc.Enabled(ctx, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := svc.ListRules(ctx, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		return on, rules
	}

	if rr := do(http.MethodPost, "", `{"cidr":"203.0.113.0/24","action":"allow"}`); rr.Code != http.StatusCreated {
		t.Fatalf("add an office rule while off: %d %s", rr.Code, rr.Body.String())
	}
	lockedOut(t, "switching on rules that leave the admin out", do(http.MethodPut, "/config", `{"enabled":true}`))
	if on, _ := state(t); on {
		t.Fatal("refused switch-on left the rules enforced")
	}

	rr := do(http.MethodPost, "", `{"cidr":"192.0.2.0/24","action":"allow","label":"admins"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("allow the admin's network: %d %s", rr.Code, rr.Body.String())
	}
	var own ipallow.Rule
	_ = json.Unmarshal(rr.Body.Bytes(), &own)
	if rr := do(http.MethodPut, "/config", `{"enabled":true}`); rr.Code != http.StatusOK {
		t.Fatalf("switch on with the admin allowed: %d %s", rr.Code, rr.Body.String())
	}

	lockedOut(t, "removing the rule that allows the admin", do(http.MethodDelete, "/"+own.ID.String(), ""))
	lockedOut(t, "denying the admin's own address", do(http.MethodPost, "", `{"cidr":"192.0.2.1/32","action":"deny"}`))
	if on, rules := state(t); !on || len(rules) != 2 {
		t.Fatalf("refused changes altered the rules: enabled=%v, %d rule(s), want 2", on, len(rules))
	}

	if rr := do(http.MethodPut, "/config", `{"enabled":false}`); rr.Code != http.StatusOK {
		t.Fatalf("switching the rules off: %d %s", rr.Code, rr.Body.String())
	}
}
