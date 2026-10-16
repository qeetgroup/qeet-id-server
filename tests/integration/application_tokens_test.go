//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An access token an application receives on a user's behalf names the
// application (client_id) and is refused by the management API — it was
// approved for the application, not for managing the account — while the
// endpoint that returns the signed-in user's own claims still accepts it. The
// user's own (first-party) tokens are unchanged.

type appTokenFixture struct {
	issuer   *tokens.Issuer
	auth     *auth.Service
	oidc     *oidc.Service
	router   http.Handler
	tenantID uuid.UUID
	clientID string
	secret   string
}

func newAppTokenFixture(t *testing.T, ctx context.Context) *appTokenFixture {
	t.Helper()
	issuer := mustIssuer()
	f := &appTokenFixture{issuer: issuer, oidc: oidc.NewService(testPool, issuer), tenantID: createTenant(t, ctx, uniqueSlug("apptokens"))}
	f.auth = auth.NewService(testPool, user.NewRepository(testPool), issuer) // the same keys as the router verifies with
	c, secret := registerOIDCClient(t, ctx, f.oidc, f.tenantID, "https://app.example/cb")
	f.clientID, f.secret = c.ClientID, secret

	authH := &auth.Handler{Service: f.auth, Validate: validator.New()}
	oidcH := &oidc.Handler{Service: f.oidc, Sessions: f.auth}
	users := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: f.auth}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		r.Use(httpx.RefuseApplicationTokens(bootstrap.ApplicationTokenRoutes()))
		authH.MountAuthed(r)
		oidcH.Mount(r)
		users.Mount(r)
	})
	f.router = r
	return f
}

// appToken signs userID in to the fixture's application through the
// authorization code flow and returns the access token it receives.
func (f *appTokenFixture) appToken(t *testing.T, ctx context.Context, userID uuid.UUID, scopes ...string) *oidc.TokenResponse {
	t.Helper()
	code, _, err := f.oidc.Authorize(ctx, userID, f.clientID, "https://app.example/cb", scopes, "", "", "")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	issued, err := f.oidc.ExchangeCode(ctx, f.clientID, f.secret, code, "https://app.example/cb", "", "")
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	return issued
}

func (f *appTokenFixture) call(method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, req)
	return rr
}

// TestApplicationTokensNameTheApplication: every token the authorization
// server hands an application — from a code, and from renewing it — names the
// application; the user's own tokens do not.
func TestApplicationTokensNameTheApplication(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newAppTokenFixture(t, ctx)
	me := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, me, f.tenantID)

	issued := f.appToken(t, ctx, me, "openid", "email")
	renewed, err := f.oidc.RefreshToken(ctx, f.clientID, f.secret, issued.RefreshToken, "")
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	for name, tok := range map[string]string{"from a code": issued.AccessToken, "renewed": renewed.AccessToken} {
		c, err := f.issuer.VerifyAccess(tok)
		if err != nil {
			t.Fatalf("verify %s token: %v", name, err)
		}
		if c.ClientID != f.clientID {
			t.Errorf("token %s names client %q, want %q", name, c.ClientID, f.clientID)
		}
	}
	own, err := f.auth.IssuePair(ctx, me, f.tenantID, "198.51.100.7", "console", "password")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	c, err := f.issuer.VerifyAccess(own.AccessToken)
	if err != nil {
		t.Fatalf("verify the user's own token: %v", err)
	}
	if c.ClientID != "" {
		t.Fatalf("the user's own token names client %q, want none", c.ClientID)
	}
}

// TestManagementAPIRefusesApplicationTokens: a token a tenant owner approved
// for identity and email cannot list or end their sessions or delete a user —
// the request is refused and nothing changes — but it still reads the user's
// own claims; the owner's own token keeps working.
func TestManagementAPIRefusesApplicationTokens(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newAppTokenFixture(t, ctx)
	owner := createUserInTenant(t, ctx, f.tenantID)
	addTenantMembership(t, ctx, owner, f.tenantID)
	victim := createUserInTenant(t, ctx, f.tenantID)
	own, err := f.auth.IssuePair(ctx, owner, f.tenantID, "198.51.100.7", "console", "password")
	if err != nil {
		t.Fatalf("sign in: %v", err)
	}
	app := f.appToken(t, ctx, owner, "openid", "email").AccessToken

	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/v1/auth/sessions"},
		{http.MethodDelete, "/v1/auth/sessions/" + own.SessionID.String()},
		{http.MethodDelete, "/v1/users/" + victim.String()},
	} {
		rr := f.call(req.method, req.path, app)
		if rr.Code != http.StatusForbidden || errorCode(t, rr) != "auth.application_token" {
			t.Errorf("%s %s with an application token = %d %q, want 403 auth.application_token", req.method, req.path, rr.Code, errorCode(t, rr))
		}
	}
	if n := liveSessionCount(t, ctx, owner); n != 1 {
		t.Errorf("owner's live sessions = %d, want the one untouched", n)
	}
	var deleted bool
	if err := testPool.QueryRow(ctx, `SELECT deleted_at IS NOT NULL FROM "user".users WHERE id = $1`, victim).Scan(&deleted); err != nil || deleted {
		t.Fatalf("victim deleted = %v (err %v), want untouched", deleted, err)
	}

	if rr := f.call(http.MethodGet, "/v1/oauth/userinfo", app); rr.Code != http.StatusOK {
		t.Fatalf("userinfo with the application token = %d %s, want 200", rr.Code, rr.Body.String())
	}
	if rr := f.call(http.MethodGet, "/v1/auth/sessions", own.AccessToken); rr.Code != http.StatusOK {
		t.Fatalf("the owner's own token on their session list = %d, want 200", rr.Code)
	}
}
