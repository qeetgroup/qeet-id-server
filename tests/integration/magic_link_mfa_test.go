//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/access/recovery"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Completing a magic link meets the same second-factor decision as password
// sign-in: an account holding a factor, or required to have one, gets a
// challenge instead of a session. The link is spent first, so a failed or
// abandoned challenge leaves neither a session nor a link to use again.

type magicMFAFixture struct {
	*factorFixture
	mail *captureSender
}

func newMagicMFAFixture(t *testing.T, ctx context.Context) *magicMFAFixture {
	t.Helper()
	f := &magicMFAFixture{factorFixture: newFactorFixture(t, ctx), mail: &captureSender{}}
	f.auth.SetDevicePolicy(authpolicy.NewService(testPool))
	links := newRecovery(f.mail)
	links.SetHostedLogin("http://login.test")
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		(&auth.Handler{Service: f.auth, Validate: validator.New()}).Mount(r)
		(&recovery.Handler{Service: links, AuthService: f.auth}).Mount(r)
	})
	f.router = r
	return f
}

// consoleLink asks for a console magic link and returns its token.
func (f *magicMFAFixture) consoleLink(t *testing.T, email string) string {
	t.Helper()
	if rr := f.post("/v1/auth/magic-link/start", map[string]string{"email": email}); rr.Code != http.StatusOK {
		t.Fatalf("magic link: %d %s", rr.Code, rr.Body.String())
	}
	return f.lastToken(t)
}

// hostedLink asks for a hosted-login magic link and returns its token.
func (f *magicMFAFixture) hostedLink(t *testing.T, email string) string {
	t.Helper()
	if rr := f.post("/v1/auth/magic-link/start", map[string]string{
		"tenant_id": f.tenantID.String(), "email": email, "app": "hosted_login",
	}); rr.Code != http.StatusOK {
		t.Fatalf("hosted magic link: %d %s", rr.Code, rr.Body.String())
	}
	return f.lastToken(t)
}

func (f *magicMFAFixture) lastToken(t *testing.T) string {
	t.Helper()
	m, ok := f.mail.last()
	if !ok {
		t.Fatal("no magic link was sent")
	}
	u, err := url.Parse(m.TemplateVariables["magic_url"])
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

func (f *magicMFAFixture) consume(t *testing.T, token string) (*httptest.ResponseRecorder, enforced) {
	t.Helper()
	rr := f.post("/v1/auth/magic-link/consume", map[string]string{"token": token})
	var e enforced
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	return rr, e
}

// lastSignInMethod is the method of the account's latest token sign-in.
func lastSignInMethod(t *testing.T, ctx context.Context, userID uuid.UUID) string {
	t.Helper()
	var method string
	if err := testPool.QueryRow(ctx, `
		SELECT metadata->>'method' FROM audit.events WHERE actor_user_id = $1 AND action = 'auth.login_succeeded'
		ORDER BY created_at DESC LIMIT 1`, userID).Scan(&method); err != nil {
		t.Fatalf("no sign-in audited: %v", err)
	}
	return method
}

// TestMagicLinkChallengesAnAccountHoldingAFactor: a console link for an
// account holding a factor answers a challenge and no token pair; a valid
// code issues the pair, audited as a magic-link sign-in that met a second
// factor.
func TestMagicLinkChallengesAnAccountHoldingAFactor(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	me, email := f.member(t, ctx)
	secret := f.holdTOTP(t, ctx, me)

	rr, e := f.consume(t, f.consoleLink(t, email))
	if rr.Code != http.StatusOK || !e.MFARequired || e.AccessToken != "" || len(e.Factors) == 0 {
		t.Fatalf("consume: %d %s, want a challenge and no tokens", rr.Code, rr.Body.String())
	}
	var firstFactor string
	if err := testPool.QueryRow(ctx, `
		SELECT metadata->>'first_factor' FROM audit.events WHERE resource_id = $1 AND action = 'auth.mfa_challenged'
		ORDER BY created_at DESC LIMIT 1`, me).Scan(&firstFactor); err != nil || firstFactor != "magic_link" {
		t.Fatalf("challenge audited with first factor %q (%v), want magic_link", firstFactor, err)
	}

	rr, done := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": e.MFAToken, "code": totpCodeAtStep(t, secret, 0)})
	if rr.Code != http.StatusOK || done.AccessToken == "" {
		t.Fatalf("completing: %d %s", rr.Code, rr.Body.String())
	}
	if m := lastSignInMethod(t, ctx, me); m != "magic_link_mfa" {
		t.Fatalf("sign-in method %q, want magic_link_mfa", m)
	}
	var verified int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM audit.events WHERE resource_id = $1 AND action = 'auth.mfa_verified'
		AND metadata->>'first_factor' = 'magic_link'`, me).Scan(&verified); err != nil || verified != 1 {
		t.Fatalf("auth.mfa_verified for the link: %d (%v), want 1", verified, err)
	}
}

// TestMagicLinkFailedChallengeLeavesNothing: a wrong code issues no pair and
// counts against the account's sign-in budget, and the link cannot be used
// again — nor after a challenge is abandoned.
func TestMagicLinkFailedChallengeLeavesNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	me, email := f.member(t, ctx)
	f.holdTOTP(t, ctx, me)

	token := f.consoleLink(t, email)
	_, e := f.consume(t, token)
	rr, done := f.completeEnforced("/v1/auth/mfa", map[string]any{"mfa_token": e.MFAToken, "code": "000000"})
	if rr.Code == http.StatusOK || done.AccessToken != "" {
		t.Fatalf("a wrong code signed in: %s", rr.Body.String())
	}
	var failed int
	if err := testPool.QueryRow(ctx, `
		SELECT failed_attempts FROM auth.mfa_attempt_budgets WHERE user_id = $1 AND purpose = 'login'`, me).Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("login budget failures %d (%v), want 1", failed, err)
	}
	if rr, _ := f.consume(t, token); errorCode(t, rr) != errs.CodeRecoveryLinkUsed {
		t.Fatalf("the link was usable again after a failed challenge: %d %s", rr.Code, rr.Body.String())
	}

	// Abandoned: the challenge is never answered, and the link stays spent.
	abandoned := f.consoleLink(t, email)
	if _, e := f.consume(t, abandoned); !e.MFARequired {
		t.Fatal("no challenge")
	}
	if rr, e := f.consume(t, abandoned); errorCode(t, rr) != errs.CodeRecoveryLinkUsed || e.AccessToken != "" {
		t.Fatalf("an abandoned challenge's link reopened: %d %s", rr.Code, rr.Body.String())
	}
}

// TestMagicLinkWithoutAFactorSignsInAsBefore: an account holding no factor
// (and not required to) gets its pair at once, audited as a plain magic-link
// sign-in.
func TestMagicLinkWithoutAFactorSignsInAsBefore(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	me, email := f.member(t, ctx)

	rr, e := f.consume(t, f.consoleLink(t, email))
	if rr.Code != http.StatusOK || e.MFARequired || e.AccessToken == "" {
		t.Fatalf("consume: %d %s, want a token pair", rr.Code, rr.Body.String())
	}
	if m := lastSignInMethod(t, ctx, me); m != "magic_link" {
		t.Fatalf("sign-in method %q, want magic_link", m)
	}
}

// TestMagicLinkMeetsTheOrganisationRequirement: where the organisation
// requires MFA, a link for an account holding no factor answers an enrolment
// challenge, not a session.
func TestMagicLinkMeetsTheOrganisationRequirement(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	requireMFA(t, ctx, f.tenantID, "required", 0, nil)
	_, email := f.member(t, ctx)

	if _, e := f.consume(t, f.consoleLink(t, email)); !e.EnrollmentRequired || e.AccessToken != "" {
		t.Fatalf("consume: %+v, want an enrolment challenge", e)
	}
	rr := f.post("/v1/auth/magic-link/session", map[string]string{"token": f.hostedLink(t, email)})
	var e enforced
	_ = json.Unmarshal(rr.Body.Bytes(), &e)
	if !e.EnrollmentRequired || rr.Header().Get("Set-Cookie") != "" {
		t.Fatalf("hosted exchange: %d %s, want an enrolment challenge and no cookie", rr.Code, rr.Body.String())
	}
}

// TestHostedMagicLinkTrustedDevice: the hosted-login link is challenged like
// the hosted password sign-in — and skips the challenge on a device the
// account trusts where the organisation allows it, on the same terms.
func TestHostedMagicLinkTrustedDevice(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	me, email := f.member(t, ctx)
	secret := f.holdTOTP(t, ctx, me)

	exchange := func(token, trusted string) (*httptest.ResponseRecorder, enforced) {
		raw, _ := json.Marshal(map[string]string{"token": token})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/magic-link/session", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		if trusted != "" {
			req.AddCookie(&http.Cookie{Name: auth.TrustedDeviceCookie, Value: trusted})
		}
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		var e enforced
		_ = json.Unmarshal(rr.Body.Bytes(), &e)
		return rr, e
	}

	rr, e := exchange(f.hostedLink(t, email), "")
	if !e.MFARequired || rr.Header().Get("Set-Cookie") != "" {
		t.Fatalf("hosted exchange: %d %s, want a challenge and no cookie", rr.Code, rr.Body.String())
	}
	rr, done := f.completeEnforced("/v1/auth/session/mfa", map[string]any{"mfa_token": e.MFAToken, "code": totpCodeAtStep(t, secret, 0)})
	if rr.Code != http.StatusOK || done.UserID == "" || !strings.Contains(rr.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("completing: %d %s", rr.Code, rr.Body.String())
	}

	// A trusted device is honoured only where the organisation allows it.
	if _, err := testPool.Exec(ctx, `
		INSERT INTO tenant.auth_policy (tenant_id, remember_device_enabled) VALUES ($1, TRUE)
		ON CONFLICT (tenant_id) DO UPDATE SET remember_device_enabled = TRUE`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	device, err := f.auth.MaybeRememberDevice(ctx, me, f.tenantID, "test")
	if err != nil || device == "" {
		t.Fatalf("remember device: %q %v", device, err)
	}
	rr, e = exchange(f.hostedLink(t, email), device)
	if e.MFARequired || !strings.Contains(rr.Header().Get("Set-Cookie"), "qe_ls=") {
		t.Fatalf("trusted device: %d %s, want the session without a challenge", rr.Code, rr.Body.String())
	}
	if _, err := testPool.Exec(ctx, `UPDATE tenant.auth_policy SET remember_device_enabled = FALSE WHERE tenant_id = $1`, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, e := exchange(f.hostedLink(t, email), device); !e.MFARequired {
		t.Fatal("a trusted device skipped the challenge where the organisation no longer allows it")
	}
}

// TestSpentOrExpiredMagicLinkIsRefusedFirst: an expired or used link is
// refused before any second-factor decision — no challenge is raised.
func TestSpentOrExpiredMagicLinkIsRefusedFirst(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newMagicMFAFixture(t, ctx)
	me, email := f.member(t, ctx)
	f.holdTOTP(t, ctx, me)

	expired := f.consoleLink(t, email)
	if _, err := testPool.Exec(ctx, `UPDATE auth.magic_links SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1`,
		codes.Hash(expired)); err != nil {
		t.Fatal(err)
	}
	if rr, _ := f.consume(t, expired); errorCode(t, rr) != errs.CodeRecoveryLinkExpired {
		t.Fatalf("expired link: %d %s", rr.Code, rr.Body.String())
	}
	var challenges int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.mfa_login_challenges WHERE user_id = $1`, me).Scan(&challenges); err != nil || challenges != 0 {
		t.Fatalf("challenges raised for a refused link: %d (%v)", challenges, err)
	}
}
