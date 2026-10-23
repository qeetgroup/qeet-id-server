package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestNoStoreRoutesAreMounted keeps the no-store list in step with the router:
// an entry that no longer names a route would silently stop applying.
func TestNoStoreRoutesAreMounted(t *testing.T) {
	mounted := productionRouteInventory(t)
	seen := map[string]bool{}
	for _, route := range NoStoreRoutes() {
		if seen[route] {
			t.Errorf("%s is listed twice", route)
		}
		seen[route] = true
		if _, ok := mounted[route]; !ok {
			t.Errorf("%s is not a mounted route", route)
		}
	}
}

// TestRouterAnswersTheTokenEndpointUncacheable checks that NewRouter applies
// the no-store list, including to a token endpoint's error.
func TestRouterAnswersTheTokenEndpointUncacheable(t *testing.T) {
	router := NewRouter(routeInventoryDeps(t))
	req := httptest.NewRequest(http.MethodPost, "/v1/oauth/token-code", strings.NewReader("grant_type=unknown"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 (%s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Errorf("Cache-Control %q, Pragma %q; want no-store, no-cache",
			rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
	}
}

// TestTokenAndSecretResponsesAreNotStored checks that the token endpoints,
// sign-in and secrets shown once are answered as uncacheable.
func TestTokenAndSecretResponsesAreNotStored(t *testing.T) {
	h := httpx.NoStore(NoStoreRoutes())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	const tenant, id = "/v1/tenants/0b8e2c7e-6a4f-4d8e-9a43-3f0c2b1d5e6a", "8c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/oauth/token"},
		{http.MethodPost, "/v1/oauth/token-code"},
		{http.MethodPost, "/v1/oauth/device_authorization"},
		{http.MethodPost, "/v1/oauth/bc-authorize"},
		{http.MethodPost, "/v1/auth/login"},
		{http.MethodPost, "/v1/auth/refresh"},
		{http.MethodPost, "/v1/auth/session"},
		{http.MethodPost, "/v1/api-keys"},
		{http.MethodPost, tenant + "/oidc/clients/" + id + "/rotate-secret"},
		{http.MethodPost, "/v1/mfa/recovery-codes/regenerate"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s: Cache-Control %q, want no-store", tc.method, tc.path, got)
		}
		if got := rec.Header().Get("Pragma"); got != "no-cache" {
			t.Errorf("%s %s: Pragma %q, want no-cache", tc.method, tc.path, got)
		}
	}
}

// TestIdempotentRoutesAreMountedCreates checks that every route honouring an
// Idempotency-Key is a mounted authenticated POST, the only kind the
// middleware sits in front of.
func TestIdempotentRoutesAreMountedCreates(t *testing.T) {
	mounted := productionRouteInventory(t)
	for _, route := range IdempotentRoutes() {
		class, ok := mounted[route]
		if !ok || !class.authenticated || !strings.HasPrefix(route, "POST ") {
			t.Errorf("%s is not a mounted authenticated POST route", route)
		}
	}
}
