//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	apikey "github.com/qeetgroup/qeet-id-server/internal/developer/api-keys"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

// TestALibraryWriteIsAuthorisedByTheKeyNotRefusedCrossSite: the cross-site
// check let only a bearer token skip it, so every write the server libraries
// make with an API key — sending no Origin, as a server does — was refused
// with csrf_failed, and so were back ends exchanging service-principal or
// directory credentials. Driven through the production check and the
// authenticated chain in production order, a library-shaped write is now
// decided by the key's scopes, and the two exchanges reach their handlers.
func TestALibraryWriteIsAuthorisedByTheKeyNotRefusedCrossSite(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tenantID := createTenant(t, ctx, uniqueSlug("library"))
	keys := apikey.NewService(testPool)
	keyWith := func(t *testing.T, scopes ...string) string {
		t.Helper()
		_, raw, err := keys.Create(ctx, apikey.CreateInput{TenantID: tenantID, Name: uniqueSlug("server"), Scopes: scopes, Actor: audit.Actor{Type: "system"}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	authSvc, _ := newAuth()
	router := chi.NewRouter()
	router.Use(bootstrap.CSRF([]string{"https://console.example"}, true, ""))
	router.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			(&principal.Handler{Service: principal.NewService(testPool, mustIssuer())}).MountPublic(r)
			(&ldap.Handler{Service: ldap.NewService(testPool, authSvc, egress.DevelopmentPolicy())}).MountPublic(r)
		})
		r.Group(func(r chi.Router) {
			r.Use(keys.Middleware)
			r.Use(httpx.RequireAuth(&httpx.AuthVerifier{}))
			r.Use(httpx.EnforceTenantScope)
			r.Use(rbac.Enforce(rbac.NewRepository(testPool), bootstrap.RoutePolicies()))
			(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New()}).Mount(r)
		})
	})
	call := func(method, path, authorization, contentType, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	refusedCrossSite := func(rr *httptest.ResponseRecorder) bool {
		return rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "csrf_failed")
	}
	createUser := func(key string) *httptest.ResponseRecorder {
		return call(http.MethodPost, "/v1/users", "ApiKey "+key, "application/json",
			`{"email":"`+uniqueSlug("made-by-library")+`@example.com"}`)
	}

	if rr := createUser(keyWith(t, "user.write")); rr.Code != http.StatusCreated {
		t.Fatalf("an API-key write with no Origin = %d %s, want 201", rr.Code, rr.Body.String())
	}
	// The key's scopes decide, not the cross-site check.
	if rr := createUser(keyWith(t, "user.read")); refusedCrossSite(rr) || rr.Code != http.StatusForbidden {
		t.Fatalf("an API-key write without the scope = %d %s, want refused for the scope", rr.Code, rr.Body.String())
	}

	tokenExchange := call(http.MethodPost, "/v1/oauth/token", "", "application/x-www-form-urlencoded",
		url.Values{"grant_type": {"client_credentials"}, "client_id": {"sp_" + uuid.NewString()}, "client_secret": {"wrong"}}.Encode())
	if refusedCrossSite(tokenExchange) || tokenExchange.Code == http.StatusNotFound {
		t.Fatalf("a service-principal token exchange with no Origin = %d %s, want it to reach the handler", tokenExchange.Code, tokenExchange.Body.String())
	}
	directory := call(http.MethodPost, "/v1/ldap/"+uuid.NewString()+"/authenticate", "", "application/json", `{"username":"someone","password":"x"}`)
	if refusedCrossSite(directory) {
		t.Fatalf("a directory sign-in with no Origin = %d %s, want it to reach the handler", directory.Code, directory.Body.String())
	}

	// Browser traffic still needs the check.
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://console.example")
	req.AddCookie(&http.Cookie{Name: "qe_ls", Value: "session"})
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if !refusedCrossSite(rr) {
		t.Fatalf("a cookie change without the CSRF token = %d %s, want csrf_failed", rr.Code, rr.Body.String())
	}
}
