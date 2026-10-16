//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// An organisation's authentication policy decides which sign-in methods its
// people may use. Turning a method off refuses it where a credential is
// accepted — password, passkey, magic link — with an access decision that is
// not a wrong-credential answer and says nothing about the account; turning it
// back on works on the next attempt; the hosted login is told which methods to
// offer; and a policy that would leave no way in, or switches on a one-time
// code sign-in that does not exist, is refused.

// setSignInMethods writes an organisation's method switches (and magic-link
// lifetime) directly.
func setSignInMethods(t *testing.T, ctx context.Context, tenantID uuid.UUID, password, passkey, magic bool, ttlMinutes int) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, password_enabled, passkey_enabled, magic_link_enabled, magic_link_ttl_minutes)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET password_enabled = EXCLUDED.password_enabled,
		    passkey_enabled = EXCLUDED.passkey_enabled, magic_link_enabled = EXCLUDED.magic_link_enabled,
		    magic_link_ttl_minutes = EXCLUDED.magic_link_ttl_minutes`,
		tenantID, password, passkey, magic, ttlMinutes); err != nil {
		t.Fatalf("set sign-in methods: %v", err)
	}
}

// clientIn registers an application owned by tenantID and returns its id.
func clientIn(t *testing.T, ctx context.Context, tenantID uuid.UUID) string {
	t.Helper()
	svc := oidc.NewService(testPool, mustIssuer())
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	c, _, err := svc.RegisterClient(ctx, tx, oidc.CreateClientInput{TenantID: tenantID, Name: "App", RedirectURIs: []string{"https://app.example/cb"}})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return c.ClientID
}

// TestPasswordSignInFollowsTheMethodPolicy covers the password criteria: with
// password sign-in off for the organisation, the hosted login (which names the
// application) is refused before any password is checked — the same answer
// for the right password, a wrong one and an address with no account — and
// the console sign-in (the account's own organisation) is refused after the
// password is verified; switching it back on works on the next attempt.
func TestPasswordSignInFollowsTheMethodPolicy(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc, _ := newAuth()
	tenantID := createTenant(t, ctx, uniqueSlug("methods-pw"))
	client := clientIn(t, ctx, tenantID)
	const pw = "Correct-Horse-Battery-71"
	_, email := userWithPassword(t, ctx, tenantID, pw)
	setSignInMethods(t, ctx, tenantID, false, true, true, 60)

	for name, attempt := range map[string]auth.SignInAttempt{
		"right password":  {Email: email, Password: pw, ClientID: client},
		"wrong password":  {Email: email, Password: "Wrong-Password-1", ClientID: client},
		"no such account": {Email: uniqueSlug("nobody") + "@example.com", Password: pw, ClientID: client},
	} {
		if _, err := svc.BeginLoginSession(ctx, attempt, "browser", "", ""); !errors.Is(err, errs.ErrAuthMethodDisabled) {
			t.Errorf("hosted sign-in (%s) err = %v, want the method-disabled decision", name, err)
		}
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: pw}); !errors.Is(err, errs.ErrAuthMethodDisabled) {
		t.Fatalf("console sign-in err = %v, want the method-disabled decision", err)
	}

	setSignInMethods(t, ctx, tenantID, true, true, true, 60)
	if _, err := svc.BeginLoginSession(ctx, auth.SignInAttempt{Email: email, Password: pw, ClientID: client}, "browser", "", ""); err != nil {
		t.Fatalf("hosted sign-in after switching password back on: %v", err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: pw}); err != nil {
		t.Fatalf("console sign-in after switching password back on: %v", err)
	}
}

// TestPasskeySignInFollowsTheMethodPolicy: with passkeys off for the account's
// organisation, the assertion endpoint refuses before verifying — an assertion
// whose signature would fail verification gets the same refusal as a valid
// one — and switching passkeys back on lets the next sign-in through.
func TestPasskeySignInFollowsTheMethodPolicy(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := newPasskeySvc(t)
	svc.SetMethodPolicy(authpolicy.NewService(testPool))
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	authenticator := virtualwebauthn.NewAuthenticator()
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)

	email := uniqueSlug("methods-pk") + "@example.com"
	sid, creation, err := svc.BeginSignup(ctx, email, "Pat")
	if err != nil {
		t.Fatalf("begin signup: %v", err)
	}
	raw, _ := json.Marshal(creation)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	if err != nil {
		t.Fatalf("parse attestation options: %v", err)
	}
	if _, _, err := svc.FinishSignup(ctx, sid, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, authenticator, cred, *attOpts)), "Laptop", "203.0.113.7", "ua"); err != nil {
		t.Fatalf("finish signup: %v", err)
	}
	authenticator.AddCredential(cred)
	authenticator.Options.UserHandle = []byte(attOpts.UserID) // so a discoverable sign-in names the account
	tenantID := createTenant(t, ctx, uniqueSlug("methods-pk"))
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET tenant_id = $2 WHERE email = $1`, email, tenantID); err != nil {
		t.Fatalf("move the account into the organisation: %v", err)
	}

	// assert signs in with the passkey: discoverable (as both sign-in pages do)
	// unless byEmail, optionally with a signature that cannot verify.
	assert := func(tamper, byEmail bool) error {
		t.Helper()
		who := ""
		if byEmail {
			who = email
		}
		loginSID, assertion, err := svc.BeginLogin(ctx, who)
		if err != nil {
			t.Fatalf("begin login: %v", err)
		}
		raw, _ := json.Marshal(assertion)
		opts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
		if err != nil {
			t.Fatalf("parse assertion options: %v", err)
		}
		resp := virtualwebauthn.CreateAssertionResponse(rp, authenticator, cred, *opts)
		if tamper {
			var body map[string]any
			_ = json.Unmarshal([]byte(resp), &body)
			body["response"].(map[string]any)["signature"] = "AAAA"
			b, _ := json.Marshal(body)
			resp = string(b)
		}
		_, err = svc.FinishLogin(ctx, loginSID, json.RawMessage(resp), "203.0.113.7", "ua")
		return err
	}

	setSignInMethods(t, ctx, tenantID, true, false, true, 60)
	for _, byEmail := range []bool{false, true} {
		if err := assert(true, byEmail); !errors.Is(err, errs.ErrPasskeyDisabled) {
			t.Fatalf("an assertion that would fail verification (by email: %v) got %v, want the passkeys-disabled decision (refused before verifying)", byEmail, err)
		}
		if err := assert(false, byEmail); !errors.Is(err, errs.ErrPasskeyDisabled) {
			t.Fatalf("a valid assertion (by email: %v) got %v, want the passkeys-disabled decision", byEmail, err)
		}
	}
	setSignInMethods(t, ctx, tenantID, true, true, true, 60)
	if err := assert(false, false); err != nil {
		t.Fatalf("passkey sign-in after switching passkeys back on: %v", err)
	}
	if err := assert(true, false); !errors.Is(err, errs.ErrPasskeyLoginFailed) {
		t.Fatalf("with passkeys on, an assertion that cannot verify got %v, want the ordinary sign-in failure", err)
	}
}

// TestMagicLinksFollowTheMethodPolicy: with magic links off nothing is issued
// or emailed and the request is refused; a link already issued stops working;
// with a fifteen-minute lifetime a new link works at fourteen minutes and is
// refused at sixteen.
func TestMagicLinksFollowTheMethodPolicy(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	sender := &captureSender{}
	svc := newRecovery(sender)
	tenantID := createTenant(t, ctx, uniqueSlug("methods-ml"))
	member := createUserInTenant(t, ctx, tenantID)
	email := uniqueSlug("methods-ml") + "@example.com"
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET email = $2 WHERE id = $1`, member, email); err != nil {
		t.Fatalf("set member email: %v", err)
	}
	links := func() int {
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.magic_links WHERE email = $1`, email).Scan(&n); err != nil {
			t.Fatalf("count links: %v", err)
		}
		return n
	}
	// issue sends a link and returns its token (from the email).
	issue := func() string {
		t.Helper()
		before := sender.count()
		if err := svc.StartMagicLink(ctx, tenantID, email); err != nil {
			t.Fatalf("start magic link: %v", err)
		}
		m, ok := sender.last()
		if !ok || sender.count() != before+1 {
			t.Fatal("no magic-link email was sent")
		}
		u := m.TemplateVariables["magic_url"]
		return u[strings.Index(u, "token=")+len("token="):]
	}

	setSignInMethods(t, ctx, tenantID, true, true, false, 60)
	sent := sender.count()
	if err := svc.StartMagicLink(ctx, tenantID, email); !errors.Is(err, errs.ErrAuthMethodDisabled) {
		t.Fatalf("start with magic links off err = %v, want the method-disabled decision", err)
	}
	if links() != 0 || sender.count() != sent {
		t.Fatal("a link was issued or emailed while magic links were off")
	}

	setSignInMethods(t, ctx, tenantID, true, true, true, 15)
	issuedAt := time.Now().UTC()
	fresh := issue()
	var expires time.Time
	if err := testPool.QueryRow(ctx, `SELECT expires_at FROM auth.magic_links WHERE token_hash = $1`, codes.Hash(fresh)).Scan(&expires); err != nil {
		t.Fatalf("read link: %v", err)
	}
	if d := expires.Sub(issuedAt); d < 14*time.Minute+50*time.Second || d > 15*time.Minute+10*time.Second {
		t.Fatalf("link lives %v, want the organisation's fifteen minutes", d)
	}
	// Fourteen minutes later the link still works; sixteen minutes later it
	// does not (moving the clock by moving the expiry).
	late := issue()
	if _, err := testPool.Exec(ctx, `UPDATE auth.magic_links SET expires_at = expires_at - INTERVAL '14 minutes' WHERE token_hash = $1`, codes.Hash(fresh)); err != nil {
		t.Fatalf("age link: %v", err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE auth.magic_links SET expires_at = expires_at - INTERVAL '16 minutes' WHERE token_hash = $1`, codes.Hash(late)); err != nil {
		t.Fatalf("age link: %v", err)
	}
	if _, err := svc.ConsumeMagicLink(ctx, fresh, recovery.AuditCtx{}); err != nil {
		t.Fatalf("link at fourteen minutes: %v", err)
	}
	if _, err := svc.ConsumeMagicLink(ctx, late, recovery.AuditCtx{}); err == nil {
		t.Fatal("link at sixteen minutes was accepted")
	}

	issued := issue()
	setSignInMethods(t, ctx, tenantID, true, true, false, 15)
	if _, err := svc.ConsumeMagicLink(ctx, issued, recovery.AuditCtx{}); !errors.Is(err, errs.ErrAuthMethodDisabled) {
		t.Fatalf("a link issued before magic links were switched off got %v, want the method-disabled decision", err)
	}
}

// TestMethodPolicyWritesThatLeaveNoWayInAreRefused: switching off every
// sign-in method, or switching on an email or SMS one-time-code sign-in (which
// does not exist), is refused naming the field, and the stored policy is
// unchanged.
func TestMethodPolicyWritesThatLeaveNoWayInAreRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	svc := authpolicy.NewService(testPool)
	tenantID := createTenant(t, ctx, uniqueSlug("methods-write"))
	setSignInMethods(t, ctx, tenantID, true, true, true, 60)

	for name, change := range map[string]func(*authpolicy.Policy){
		"every method off": func(p *authpolicy.Policy) {
			p.PasswordEnabled, p.PasskeyEnabled, p.MagicLinkEnabled = false, false, false
		},
		"email one-time code": func(p *authpolicy.Policy) { p.OTPEmailEnabled = true },
		"SMS one-time code":   func(p *authpolicy.Policy) { p.OTPSMSEnabled = true },
	} {
		t.Run(name, func(t *testing.T) {
			p, err := svc.Get(ctx, tenantID)
			if err != nil {
				t.Fatalf("get policy: %v", err)
			}
			change(p)
			tx, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer tx.Rollback(ctx)
			if _, err := svc.Update(ctx, tx, tenantID, *p); !errors.Is(err, errs.ErrValidationFailed) {
				t.Fatalf("update err = %v, want a validation refusal", err)
			}
			tx.Rollback(ctx)
			after, err := svc.Get(ctx, tenantID)
			if err != nil {
				t.Fatalf("get policy: %v", err)
			}
			if !after.PasswordEnabled || !after.PasskeyEnabled || !after.MagicLinkEnabled || after.OTPEmailEnabled || after.OTPSMSEnabled {
				t.Fatalf("stored policy changed: %+v", after)
			}
		})
	}
}

// TestLoginContextReportsTheSignInMethods: the hosted login is told which
// methods the application's organisation allows, so it offers only those.
func TestLoginContextReportsTheSignInMethods(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("methods-ctx"))
	client := clientIn(t, ctx, tenantID)
	setSignInMethods(t, ctx, tenantID, false, true, true, 60)

	policy := authpolicy.NewService(testPool)
	h := &oidc.Handler{Service: oidc.NewService(testPool, mustIssuer()), Registration: policy, DeviceTrust: policy, Methods: policy, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", h.MountBrowser)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/oauth/login-context?client_id="+client, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login-context status = %d", rr.Code)
	}
	var body struct {
		Methods map[string]bool `json:"sign_in_methods"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login-context: %v", err)
	}
	want := map[string]bool{"password": false, "passkey": true, "magic_link": true}
	for k, v := range want {
		if got, ok := body.Methods[k]; !ok || got != v {
			t.Errorf("sign_in_methods[%s] = %v (present %v), want %v; got %v", k, got, ok, v, body.Methods)
		}
	}
}
