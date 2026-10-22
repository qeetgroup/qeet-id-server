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
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/social"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// Signing in with a social provider creates an account only when the
// organisation allows self-registration, like its password and passkey
// sign-up do. With it off, someone the organisation does not know is refused —
// nothing is written but an audit entry — while people who already have an
// account (linked to the provider, or matched by a verified address) sign in as
// before.

const closedRegReturnTo = "https://app.example/oauth/authorize?client_id=rp"

type closedRegFixture struct {
	svc      *social.Service
	tenantID uuid.UUID
	provider string
	idp      *httptest.Server
	email    string
	subject  string
}

func newClosedRegFixture(t *testing.T, ctx context.Context, verified bool) *closedRegFixture {
	t.Helper()
	f := &closedRegFixture{
		tenantID: createTenant(t, ctx, uniqueSlug("closedreg")),
		provider: "closedprov",
		email:    uniqueSlug("closedreg") + "@example.com",
		subject:  uniqueSlug("sub"),
	}
	f.idp = fakeIdPWithUserinfo(t, fmt.Sprintf(`{"sub":%q,"email":%q,"email_verified":%t,"name":"Someone"}`, f.subject, f.email, verified))
	t.Cleanup(f.idp.Close)
	authService, _ := newAuth()
	f.svc = social.NewService(testPool, authService, "http://app.local", egress.DevelopmentPolicy())
	f.svc.SetCipher(testEnvelope(t))
	f.svc.SetAllowedReturnOrigins("https://app.example")
	if _, err := f.svc.UpsertProvider(ctx, social.CreateProviderInput{
		TenantID: f.tenantID, Provider: f.provider, ClientID: "cid", ClientSecret: "secret",
		DiscoveryURL: f.idp.URL + "/.well-known/openid-configuration",
	}); err != nil {
		t.Fatalf("register provider: %v", err)
	}
	return f
}

// setSelfRegistration turns the organisation's self-registration on or off.
func setSelfRegistration(t *testing.T, ctx context.Context, tenantID uuid.UUID, on bool) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, self_registration_enabled) VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET self_registration_enabled = EXCLUDED.self_registration_enabled`,
		tenantID, on); err != nil {
		t.Fatalf("set self-registration: %v", err)
	}
}

// begin starts a hosted social sign-in and returns its state.
func (f *closedRegFixture) begin(t *testing.T, ctx context.Context) string {
	t.Helper()
	authURL, err := f.svc.BeginLogin(ctx, f.provider, f.tenantID.String(), "http://api.local/v1/social/"+f.provider+"/callback", closedRegReturnTo)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	u, _ := url.Parse(authURL)
	return u.Query().Get("state")
}

func (f *closedRegFixture) callback(t *testing.T, ctx context.Context) (*social.CallbackResult, error) {
	t.Helper()
	return f.svc.CompleteCallback(ctx, f.provider, f.begin(t, ctx), "upstream-code", true)
}

// leftBehind counts what a refused attempt must not leave: the account, the
// provider link, memberships, social login codes and hosted-login sessions.
func (f *closedRegFixture) leftBehind(t *testing.T, ctx context.Context) map[string]int {
	t.Helper()
	out := map[string]int{}
	for name, q := range map[string]string{
		"users":          `SELECT count(*) FROM "user".users WHERE email = $1`,
		"identities":     `SELECT count(*) FROM "user".external_identities WHERE email = $1 OR subject = $2`,
		"memberships":    `SELECT count(*) FROM rbac.user_roles ur JOIN "user".users u ON u.id = ur.user_id WHERE u.email = $1`,
		"login codes":    `SELECT count(*) FROM auth.social_login_codes c JOIN "user".users u ON u.id = c.user_id WHERE u.email = $1`,
		"login sessions": `SELECT count(*) FROM auth.login_sessions s JOIN "user".users u ON u.id = s.user_id WHERE u.email = $1`,
	} {
		var n int
		args := []any{f.email}
		if strings.Contains(q, "$2") {
			args = append(args, f.subject)
		}
		if err := testPool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", name, err)
		}
		out[name] = n
	}
	return out
}

type refusalRecord struct {
	count    int
	tenantID *uuid.UUID
	metadata map[string]any
}

func (f *closedRegFixture) refusals(t *testing.T, ctx context.Context) refusalRecord {
	t.Helper()
	var rec refusalRecord
	rows, err := testPool.Query(ctx, `
		SELECT tenant_id, metadata FROM audit.events
		WHERE action = 'social.signup_refused' AND tenant_id = $1 AND metadata->>'email' = $2`, f.tenantID, f.email)
	if err != nil {
		t.Fatalf("read refusals: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		rec.count++
		if err := rows.Scan(&rec.tenantID, &raw); err != nil {
			t.Fatalf("scan refusal: %v", err)
		}
		_ = json.Unmarshal(raw, &rec.metadata)
	}
	return rec
}

// TestSocialSignUpIntoAClosedOrganisationIsRefused: self-registration off and
// an identity the organisation does not know → refused as a closed-registration
// decision (carrying the way back to the application), nothing left behind, and
// an audit entry naming the organisation, the provider and the address.
func TestSocialSignUpIntoAClosedOrganisationIsRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, false)

	res, err := f.callback(t, ctx)
	if !errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) {
		t.Fatalf("callback err = %v, want the self-registration-disabled decision", err)
	}
	if res == nil || res.ReturnTo != closedRegReturnTo {
		t.Fatalf("refusal result = %+v, want it to carry the return_to %q", res, closedRegReturnTo)
	}
	for what, n := range f.leftBehind(t, ctx) {
		if n != 0 {
			t.Errorf("%d %s left behind by a refused attempt", n, what)
		}
	}
	rec := f.refusals(t, ctx)
	if rec.count != 1 {
		t.Fatalf("refusal audit entries = %d, want 1", rec.count)
	}
	if rec.tenantID == nil || *rec.tenantID != f.tenantID || rec.metadata["provider"] != f.provider {
		t.Fatalf("refusal entry = %+v, want the organisation and provider %q", rec, f.provider)
	}
}

// TestSocialSignInWithALinkedIdentityWorksWhenClosed: someone who already
// signed in with the provider keeps signing in after self-registration is
// switched off.
func TestSocialSignInWithALinkedIdentityWorksWhenClosed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, true)
	first, err := f.callback(t, ctx)
	if err != nil {
		t.Fatalf("first sign-in while open: %v", err)
	}
	setSelfRegistration(t, ctx, f.tenantID, false)
	again, err := f.callback(t, ctx)
	if err != nil {
		t.Fatalf("sign-in with a linked identity while closed: %v", err)
	}
	if again.UserID != first.UserID || again.Code == "" {
		t.Fatalf("second sign-in = %+v, want the same account and a login code", again)
	}
}

// TestSocialAdoptsAnInTenantAccountWhenClosed: a verified assertion for an
// account the organisation already has, whose address it has proved, is
// adopted exactly as before.
func TestSocialAdoptsAnInTenantAccountWhenClosed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, false)
	member := createUserInTenant(t, ctx, f.tenantID)
	if _, err := testPool.Exec(ctx, `UPDATE "user".users SET email = $2, email_verified_at = NOW() WHERE id = $1`, member, f.email); err != nil {
		t.Fatalf("set member email: %v", err)
	}
	res, err := f.callback(t, ctx)
	if err != nil {
		t.Fatalf("adopting an in-tenant account while closed: %v", err)
	}
	if res.UserID != member {
		t.Fatalf("signed in as %v, want the existing member %v", res.UserID, member)
	}
}

// TestSocialSignUpIntoAnOpenOrganisationProvisions: with self-registration on,
// an unknown identity gets an account as before.
func TestSocialSignUpIntoAnOpenOrganisationProvisions(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, true)
	res, err := f.callback(t, ctx)
	if err != nil {
		t.Fatalf("sign-up while open: %v", err)
	}
	if res.UserID == uuid.Nil || f.leftBehind(t, ctx)["users"] != 1 {
		t.Fatalf("sign-up while open did not provision an account: %+v", res)
	}
}

// TestSocialConcurrentSignUpsIntoAClosedOrganisationAreBothRefused: two
// callbacks for the same unknown identity at once are both refused and neither
// writes a row.
func TestSocialConcurrentSignUpsIntoAClosedOrganisationAreBothRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, false)
	states := []string{f.begin(t, ctx), f.begin(t, ctx)}
	var wg sync.WaitGroup
	results := make([]error, len(states))
	for i, st := range states {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = f.svc.CompleteCallback(ctx, f.provider, st, "upstream-code", true)
		}()
	}
	wg.Wait()
	for i, err := range results {
		if !errors.Is(err, errs.ErrAuthSelfRegistrationDisabled) {
			t.Errorf("callback %d err = %v, want the self-registration-disabled decision", i+1, err)
		}
	}
	if n := f.leftBehind(t, ctx)["users"]; n != 0 {
		t.Fatalf("%d accounts created by concurrent refused callbacks", n)
	}
}

// TestSocialRefusalTellsThePersonRegistrationIsClosed: the browser is sent back
// to the hosted login with a closed-registration error — not the generic
// provider failure — and the way back to the application.
func TestSocialRefusalTellsThePersonRegistrationIsClosed(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newClosedRegFixture(t, ctx, true)
	setSelfRegistration(t, ctx, f.tenantID, false)
	h := &social.Handler{Service: f.svc, LoginBaseURL: "http://login.test"}
	r := chi.NewRouter()
	r.Route("/v1", h.MountPublic)

	req := socialCallback(f.provider, f.begin(t, ctx))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	loc, err := url.Parse(rr.Header().Get("Location"))
	if rr.Code != http.StatusFound || err != nil {
		t.Fatalf("callback = %d %q, want a redirect", rr.Code, rr.Header().Get("Location"))
	}
	if loc.Host != "login.test" || loc.Path != "/login" || loc.Query().Get("error") != "registration_closed" {
		t.Fatalf("redirect = %q, want hosted login with error=registration_closed", loc)
	}
	if got := loc.Query().Get("return_to"); got != closedRegReturnTo {
		t.Fatalf("redirect return_to = %q, want %q", got, closedRegReturnTo)
	}
}
