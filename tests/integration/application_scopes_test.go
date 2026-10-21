//go:build integration

package integration

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestApplicationTokensNeedTheRouteScope: on a route open to applications, a
// token issued to an application acts for its user only where the user's role
// grants the route's permission and the user approved the route's scope. The
// router is the production chain (RequireAuth, RefuseApplicationTokens,
// EnforceTenantScope, rbac.Enforce with bootstrap.RoutePolicies), with one
// management route, GET /v1/users, opened to applications as a later product
// decision would. The user's own tokens are decided by their role alone.
func TestApplicationTokensNeedTheRouteScope(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	issuer := mustIssuer()
	oidcSvc := oidc.NewService(testPool, issuer)
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	repo := rbac.NewRepository(testPool)
	tenantID := createTenant(t, ctx, uniqueSlug("appscopes"))

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	client, secret, err := oidcSvc.RegisterClient(ctx, tx, oidc.CreateClientInput{
		TenantID: tenantID, Name: "RP", RedirectURIs: []string{"https://app.example/cb"},
		Scopes: []string{"openid", "email", "user.read"},
	})
	if err != nil {
		t.Fatalf("register client: %v", err)
	}
	perm, err := repo.UpsertPermission(ctx, tx, "user.read", "read users")
	if err != nil {
		t.Fatalf("permission: %v", err)
	}
	role, err := repo.CreateRole(ctx, tx, tenantID, uniqueSlug("reader"), "", false)
	if err != nil {
		t.Fatalf("role: %v", err)
	}
	if err := repo.GrantPermission(ctx, tx, role.ID, perm.ID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	reader := createUserInTenant(t, ctx, tenantID)
	if err := repo.AssignRole(ctx, tx, reader, tenantID, role.ID, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	stranger := createUserInTenant(t, ctx, tenantID) // a member whose role grants nothing
	addTenantMembership(t, ctx, stranger, tenantID)

	users := &user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: authSvc}
	oidcH := &oidc.Handler{Service: oidcSvc, Sessions: authSvc}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		r.Use(httpx.RefuseApplicationTokens(append(bootstrap.ApplicationTokenRoutes(), "GET /v1/users")))
		r.Use(httpx.EnforceTenantScope)
		r.Use(rbac.Enforce(repo, bootstrap.RoutePolicies()))
		users.Mount(r)
		oidcH.Mount(r)
	})
	call := func(method, path, token string) (int, string, string) {
		f := &appTokenFixture{router: r}
		rr := f.call(method, path, token)
		return rr.Code, errorCode(t, rr), rr.Header().Get("WWW-Authenticate")
	}
	appToken := func(userID uuid.UUID, scopes ...string) string {
		t.Helper()
		code, _, err := oidcSvc.Authorize(ctx, userID, client.ClientID, "https://app.example/cb", scopes, testNonce, testChallenge, "S256")
		if err != nil {
			t.Fatalf("authorize %v: %v", scopes, err)
		}
		issued, err := oidcSvc.ExchangeCode(ctx, client.ClientID, secret, code, "https://app.example/cb", testVerifier, "")
		if err != nil {
			t.Fatalf("exchange code: %v", err)
		}
		return issued.AccessToken
	}

	t.Run("the scope and a permitting role reach the opened route", func(t *testing.T) {
		if code, ec, _ := call(http.MethodGet, "/v1/users", appToken(reader, "openid", "user.read")); code != http.StatusOK {
			t.Fatalf("GET /v1/users = %d %q, want 200", code, ec)
		}
	})

	t.Run("the role without the scope is refused, naming the scope", func(t *testing.T) {
		code, ec, challenge := call(http.MethodGet, "/v1/users", appToken(reader, "openid", "email"))
		if code != http.StatusForbidden || ec != "auth.insufficient_scope" {
			t.Fatalf("GET /v1/users = %d %q, want 403 auth.insufficient_scope", code, ec)
		}
		if !strings.Contains(challenge, `error="insufficient_scope"`) || !strings.Contains(challenge, `scope="user.read"`) {
			t.Fatalf("challenge %q, want insufficient_scope naming user.read", challenge)
		}
	})

	t.Run("the scope without a permitting role is refused", func(t *testing.T) {
		if code, ec, _ := call(http.MethodGet, "/v1/users", appToken(stranger, "openid", "user.read")); code != http.StatusForbidden || ec == "auth.insufficient_scope" {
			t.Fatalf("GET /v1/users = %d %q, want 403 for want of the permission", code, ec)
		}
	})

	t.Run("userinfo needs openid of an application", func(t *testing.T) {
		if code, ec, _ := call(http.MethodGet, "/v1/oauth/userinfo", appToken(reader, "openid")); code != http.StatusOK {
			t.Fatalf("userinfo with openid = %d %q, want 200", code, ec)
		}
		if code, ec, _ := call(http.MethodGet, "/v1/oauth/userinfo", appToken(reader, "user.read")); code != http.StatusForbidden || ec != "auth.insufficient_scope" {
			t.Fatalf("userinfo without openid = %d %q, want 403 auth.insufficient_scope", code, ec)
		}
	})

	t.Run("a route not opened stays closed whatever the scope", func(t *testing.T) {
		if code, ec, _ := call(http.MethodGet, "/v1/users/"+reader.String(), appToken(reader, "openid", "user.read")); code != http.StatusForbidden || ec != "auth.application_token" {
			t.Fatalf("GET /v1/users/{id} = %d %q, want 403 auth.application_token", code, ec)
		}
	})

	t.Run("the user's own token is decided by the role alone", func(t *testing.T) {
		own, err := authSvc.IssuePair(ctx, reader, tenantID, "198.51.100.7", "console", "password")
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		if code, ec, _ := call(http.MethodGet, "/v1/users", own.AccessToken); code != http.StatusOK {
			t.Fatalf("own token GET /v1/users = %d %q, want 200", code, ec)
		}
		if code, ec, _ := call(http.MethodGet, "/v1/users/"+reader.String(), own.AccessToken); code != http.StatusOK {
			t.Fatalf("own token GET /v1/users/{id} = %d %q, want 200", code, ec)
		}
	})
}
