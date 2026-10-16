//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Switching organisation replaces the session the person is using with one
// scoped to the organisation they move to. The claims that organisation's
// authentication hook adds are in the new token and stay there across
// renewals; the session left behind ends, can no longer be renewed, and is
// announced to revocation subscribers; and the person's session list keeps
// one entry per sign-in however often they switch.

// orgHook is an authentication hook whose answer depends on the organisation:
// claims to add, or a refusal.
type orgHook struct {
	claims map[uuid.UUID]map[string]any
	deny   map[uuid.UUID]bool
}

func (h orgHook) Run(_ context.Context, tenantID, _ uuid.UUID, _ string) (map[string]any, error) {
	if h.deny[tenantID] {
		return nil, errs.ErrForbidden
	}
	return h.claims[tenantID], nil
}

type sentSignal struct {
	tenantID uuid.UUID
	event    string
	payload  map[string]any
}

type tenantSwitchFixture struct {
	svc     *auth.Service
	issuer  *tokens.Issuer
	router  http.Handler
	home    uuid.UUID
	other   uuid.UUID
	foreign uuid.UUID
	hook    orgHook

	mu      sync.Mutex
	signals []sentSignal
}

func newTenantSwitchFixture(t *testing.T, ctx context.Context) *tenantSwitchFixture {
	t.Helper()
	issuer := mustIssuer()
	f := &tenantSwitchFixture{
		svc:     auth.NewService(testPool, user.NewRepository(testPool), issuer),
		issuer:  issuer,
		home:    createTenant(t, ctx, uniqueSlug("switch-home")),
		other:   createTenant(t, ctx, uniqueSlug("switch-other")),
		foreign: createTenant(t, ctx, uniqueSlug("switch-foreign")),
	}
	f.hook = orgHook{
		claims: map[uuid.UUID]map[string]any{
			f.home:  {"department": "home-dept"},
			f.other: {"department": "other-dept", "clearance": "partner"},
		},
		deny: map[uuid.UUID]bool{},
	}
	f.svc.SetLoginHook(f.hook)
	f.svc.SetEmitter(func(_ context.Context, tenantID uuid.UUID, event string, payload any) error {
		raw, _ := json.Marshal(payload)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.signals = append(f.signals, sentSignal{tenantID: tenantID, event: event, payload: m})
		return nil
	})
	h := &auth.Handler{Service: f.svc, Validate: validator.New()}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		h.MountAuthed(r)
	})
	f.router = r
	return f
}

// signIn creates a member of both organisations (home first) signed in to
// home, with home's hook claims, as a password sign-in issues them.
func (f *tenantSwitchFixture) signIn(t *testing.T, ctx context.Context) (uuid.UUID, *auth.TokenPair) {
	t.Helper()
	id := createUserInTenant(t, ctx, f.home)
	addTenantMembership(t, ctx, id, f.home)
	addTenantMembership(t, ctx, id, f.other)
	pair, err := f.svc.IssuePairWithClaims(ctx, id, f.home, "198.51.100.7", "laptop", "password", f.hook.claims[f.home])
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	return id, pair
}

type switchResult struct {
	status       int
	code         string
	accessToken  string
	refreshToken string
	sessionID    uuid.UUID
}

func (f *tenantSwitchFixture) switchTo(t *testing.T, accessToken string, tenantID uuid.UUID) switchResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/switch-tenant", strings.NewReader(`{"tenant_id":"`+tenantID.String()+`"}`))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	var body struct {
		AccessToken  string    `json:"access_token"`
		RefreshToken string    `json:"refresh_token"`
		SessionID    uuid.UUID `json:"session_id"`
		Error        struct {
			Code string `json:"code"`
		} `json:"error"`
		Code string `json:"code"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	code := body.Error.Code
	if code == "" {
		code = body.Code
	}
	return switchResult{rr.Code, code, body.AccessToken, body.RefreshToken, body.SessionID}
}

func (f *tenantSwitchFixture) customClaims(t *testing.T, accessToken string) map[string]any {
	t.Helper()
	c, err := f.issuer.VerifyAccess(accessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	return c.Custom
}

func (f *tenantSwitchFixture) revocationSignals(sessionID uuid.UUID) []sentSignal {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sentSignal
	for _, s := range f.signals {
		if s.event == "session.revoked" && s.payload["session_id"] == sessionID.String() {
			out = append(out, s)
		}
	}
	return out
}

func (f *tenantSwitchFixture) listedSessions(t *testing.T, accessToken string) (items, total int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list sessions status = %d", rr.Code)
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
		Total int               `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	return len(page.Items), page.Total
}

func liveRefreshTokenCount(t *testing.T, ctx context.Context, userID uuid.UUID) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx, `
		SELECT count(*) FROM auth.refresh_tokens rt JOIN auth.sessions s ON s.id = rt.session_id
		WHERE s.user_id = $1 AND s.revoked_at IS NULL AND rt.used_at IS NULL AND rt.expires_at > NOW()`, userID).Scan(&n); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	return n
}

// TestSwitchCarriesTheOrganisationsHookClaims: the token issued by the switch
// carries the claims the target organisation's hook adds (and not the ones the
// organisation left behind added), and a renewal keeps them.
func TestSwitchCarriesTheOrganisationsHookClaims(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newTenantSwitchFixture(t, ctx)
	_, pair := f.signIn(t, ctx)
	if got := f.customClaims(t, pair.AccessToken)["department"]; got != "home-dept" {
		t.Fatalf("signed-in token department = %v, want home-dept", got)
	}

	res := f.switchTo(t, pair.AccessToken, f.other)
	if res.status != http.StatusOK {
		t.Fatalf("switch status = %d (%s), want 200", res.status, res.code)
	}
	claims := f.customClaims(t, res.accessToken)
	if claims["department"] != "other-dept" || claims["clearance"] != "partner" {
		t.Fatalf("token after the switch carries %v, want the other organisation's hook claims", claims)
	}

	renewed, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: res.refreshToken})
	if err != nil {
		t.Fatalf("renew after the switch: %v", err)
	}
	if got := f.customClaims(t, renewed.AccessToken); got["department"] != "other-dept" || got["clearance"] != "partner" {
		t.Fatalf("renewed token carries %v, want the hook claims kept", got)
	}
}

// TestSwitchEndsTheSessionItLeaves: the session the switch was made from is
// ended — its renewal credential is refused — and revocation subscribers of
// the organisation it belonged to are told, with the switch as the reason.
func TestSwitchEndsTheSessionItLeaves(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newTenantSwitchFixture(t, ctx)
	_, pair := f.signIn(t, ctx)

	res := f.switchTo(t, pair.AccessToken, f.other)
	if res.status != http.StatusOK {
		t.Fatalf("switch status = %d (%s), want 200", res.status, res.code)
	}
	if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); !errors.Is(err, errs.ErrAuthSessionRevoked) {
		t.Fatalf("the left session still renews: err = %v", err)
	}
	signals := f.revocationSignals(pair.SessionID)
	if len(signals) != 1 {
		t.Fatalf("revocation signals for the left session = %d, want 1", len(signals))
	}
	if s := signals[0]; s.tenantID != f.home || s.payload["reason"] != "tenant_switch" {
		t.Fatalf("signal = %+v, want reason tenant_switch to the organisation left", s)
	}
	if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: res.refreshToken}); err != nil {
		t.Fatalf("the new session does not renew: %v", err)
	}
}

// TestSwitchingBackAndForthLeavesOneSession: switching repeatedly between two
// organisations leaves exactly one live session and one live renewal
// credential, and the person's session list shows that one sign-in.
func TestSwitchingBackAndForthLeavesOneSession(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newTenantSwitchFixture(t, ctx)
	me, pair := f.signIn(t, ctx)

	access := pair.AccessToken
	for i, to := range []uuid.UUID{f.other, f.home, f.other, f.home} {
		res := f.switchTo(t, access, to)
		if res.status != http.StatusOK {
			t.Fatalf("switch %d status = %d (%s), want 200", i+1, res.status, res.code)
		}
		access = res.accessToken
	}
	if n := liveSessionCount(t, ctx, me); n != 1 {
		t.Fatalf("live sessions after switching = %d, want 1", n)
	}
	if n := liveRefreshTokenCount(t, ctx, me); n != 1 {
		t.Fatalf("live renewal credentials after switching = %d, want 1", n)
	}
	if items, total := f.listedSessions(t, access); items != 1 || total != 1 {
		t.Fatalf("session list shows %d entries (total %d), want the one sign-in", items, total)
	}
}

// TestSwitchThatIsRefusedChangesNothing: a switch to an organisation the person
// does not belong to, or one whose hook refuses them, is refused, and the
// session they are using carries on unchanged.
func TestSwitchThatIsRefusedChangesNothing(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newTenantSwitchFixture(t, ctx)
	f.hook.deny[f.other] = true

	for name, to := range map[string]uuid.UUID{"not a member": f.foreign, "hook refuses": f.other} {
		t.Run(name, func(t *testing.T) {
			me, pair := f.signIn(t, ctx)
			res := f.switchTo(t, pair.AccessToken, to)
			if res.status != http.StatusForbidden {
				t.Fatalf("switch status = %d (%s), want 403", res.status, res.code)
			}
			if n := liveSessionCount(t, ctx, me); n != 1 {
				t.Fatalf("live sessions = %d, want the one in use", n)
			}
			if len(f.revocationSignals(pair.SessionID)) != 0 {
				t.Fatal("a revocation signal was sent for a refused switch")
			}
			if _, err := f.svc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken}); err != nil {
				t.Fatalf("the session in use stopped renewing: %v", err)
			}
		})
	}
}

// TestSwitchFromAnEndedSessionIsRefused: an access token outlives its session
// by a few minutes; it cannot be used to switch, which would open a new
// session for someone who has signed out.
func TestSwitchFromAnEndedSessionIsRefused(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newTenantSwitchFixture(t, ctx)
	me, pair := f.signIn(t, ctx)
	if err := f.svc.Logout(ctx, pair.SessionID, me); err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if res := f.switchTo(t, pair.AccessToken, f.other); res.status != http.StatusUnauthorized {
		t.Fatalf("switch from an ended session status = %d (%s), want 401", res.status, res.code)
	}
	if n := liveSessionCount(t, ctx, me); n != 0 {
		t.Fatalf("live sessions = %d, want none", n)
	}
}
