package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

type fakeChecker struct {
	allow bool
	calls int
}

func (f *fakeChecker) Check(_ context.Context, _, _ uuid.UUID, _ string) (bool, error) {
	f.calls++
	return f.allow, nil
}

// buildRouter mirrors the real composition: routes under /v1 with Enforce as a
// group middleware, so chi's RoutePattern resolves to e.g. "/v1/users".
func buildRouter(c Checker, p *httpx.Principal) http.Handler {
	policies := map[string]RoutePolicy{
		"POST /v1/users": PermissionPolicy("user.write"),
		"GET /v1/users":  PermissionPolicy("user.read"),
		"GET /v1/me":     UserOnlyPolicy(),
	}
	r := chi.NewRouter()
	// Inject the test principal before routing so Enforce can read it.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		})
	})
	r.Route("/v1", func(r chi.Router) {
		r.Use(Enforce(c, policies))
		r.Post("/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
		r.Get("/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		r.Get("/me", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		r.Delete("/things/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	})
	return r
}

func userPrincipal() *httpx.Principal {
	uid, tid := uuid.New(), uuid.New()
	return &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: "user"}
}

func do(h http.Handler, method, path string) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

func TestEnforce_UserAllowedAndDenied(t *testing.T) {
	allow := &fakeChecker{allow: true}
	if got := do(buildRouter(allow, userPrincipal()), "POST", "/v1/users"); got != http.StatusCreated {
		t.Fatalf("allowed user POST /v1/users = %d, want 201", got)
	}
	deny := &fakeChecker{allow: false}
	if got := do(buildRouter(deny, userPrincipal()), "POST", "/v1/users"); got != http.StatusForbidden {
		t.Fatalf("denied user POST /v1/users = %d, want 403", got)
	}
	if deny.calls != 1 {
		t.Fatalf("checker calls = %d, want 1 (RoutePattern must resolve to a mapped key)", deny.calls)
	}
}

func TestEnforce_MachineActorRequiresMatchingScope(t *testing.T) {
	for _, actorType := range []string{"api_key", "service", "agent"} {
		t.Run(actorType, func(t *testing.T) {
			deny := &fakeChecker{allow: false}
			uid, tid := uuid.New(), uuid.New()
			principal := &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: actorType, Scopes: []string{"user.read"}}
			if got := do(buildRouter(deny, principal), "POST", "/v1/users"); got != http.StatusForbidden {
				t.Fatalf("read-scoped %s POST /v1/users = %d, want 403", actorType, got)
			}
			principal.Scopes = []string{"user.write"}
			if got := do(buildRouter(deny, principal), "POST", "/v1/users"); got != http.StatusCreated {
				t.Fatalf("write-scoped %s POST /v1/users = %d, want 201", actorType, got)
			}
			if deny.calls != 0 {
				t.Fatalf("checker called %d times for %s; want 0", deny.calls, actorType)
			}
		})
	}
}

func TestEnforce_UnmappedRouteDenied(t *testing.T) {
	deny := &fakeChecker{allow: false}
	if got := do(buildRouter(deny, userPrincipal()), "DELETE", "/v1/things/abc"); got != http.StatusForbidden {
		t.Fatalf("unmapped route = %d, want 403", got)
	}
	if deny.calls != 0 {
		t.Fatalf("checker called for unmapped route; want 0")
	}
}

func TestEnforce_UserOnlyRouteRejectsMachineActor(t *testing.T) {
	allow := &fakeChecker{allow: true}
	uid, tid := uuid.New(), uuid.New()
	apiKey := &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: "api_key", Scopes: []string{"user.read"}}
	if got := do(buildRouter(allow, apiKey), "GET", "/v1/me"); got != http.StatusForbidden {
		t.Fatalf("api_key GET /v1/me = %d, want 403", got)
	}
	if got := do(buildRouter(allow, userPrincipal()), "GET", "/v1/me"); got != http.StatusOK {
		t.Fatalf("user GET /v1/me = %d, want 200", got)
	}
}

func TestEnforce_TenantlessUserOnGatedRouteDenied(t *testing.T) {
	allow := &fakeChecker{allow: true}
	uid := uuid.New()
	tenantless := &httpx.Principal{UserID: &uid, ActorType: "user"} // no TenantID
	if got := do(buildRouter(allow, tenantless), "POST", "/v1/users"); got != http.StatusForbidden {
		t.Fatalf("tenant-less user on gated route = %d, want 403", got)
	}
}

func TestValidateMachineScopes(t *testing.T) {
	for _, scopes := range [][]string{
		nil,
		{"user.read", "audit.read"},
		{"vault:read"},
		{"vault:github"},
	} {
		if err := ValidateMachineScopes(scopes); err != nil {
			t.Errorf("valid scopes %v rejected: %v", scopes, err)
		}
	}
	for _, scopes := range [][]string{{"users:read"}, {"*"}, {"vault:"}, {"unknown.write"}} {
		if err := ValidateMachineScopes(scopes); err == nil {
			t.Errorf("invalid scopes %v accepted", scopes)
		}
	}
}

// TestEnforce_MostLiteralPolicyWins pins the resolution order for overlapping
// patterns. "/v1/vault/{name}" also matches "/v1/vault/tokens", which carries a
// different policy; ranging over a map would decide the winner by iteration
// order, so the same request could be classified differently between processes.
func TestEnforce_MostLiteralPolicyWins(t *testing.T) {
	policies := map[string]RoutePolicy{
		"GET /v1/vault/tokens": UserOnlyPolicy(),
		"GET /v1/vault/{name}": HandlerAuthorizedPolicy(true),
	}
	uid, tid := uuid.New(), uuid.New()
	machine := &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: "api_key", Scopes: []string{"vault:read"}}

	// Run repeatedly: a map-order bug shows up as a flake, not a hard failure.
	for i := 0; i < 50; i++ {
		// The literal route is user-only, so a machine principal must be denied.
		if got := do(vaultRouter(policies, machine), http.MethodGet, "/v1/vault/tokens"); got != http.StatusForbidden {
			t.Fatalf("iteration %d: GET /v1/vault/tokens as api_key = %d, want 403", i, got)
		}
		// The wildcard route is handler-authorized, so it passes the middleware.
		if got := do(vaultRouter(policies, machine), http.MethodGet, "/v1/vault/db-password"); got != http.StatusOK {
			t.Fatalf("iteration %d: GET /v1/vault/db-password as api_key = %d, want 200", i, got)
		}
	}
}

// vaultRouter mounts the two overlapping vault routes with Enforce in front,
// rebuilt per call so each iteration re-runs the map->slice ordering.
func vaultRouter(policies map[string]RoutePolicy, p *httpx.Principal) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		})
	})
	r.Route("/v1", func(r chi.Router) {
		r.Use(Enforce(&fakeChecker{allow: true}, policies))
		r.Get("/vault/tokens", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		r.Get("/vault/{name}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	})
	return r
}
