package rbac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/internal/platform/httpx"
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
	perms := map[string]string{
		"POST /v1/users": "user.write",
		"GET /v1/users":  "user.read",
	}
	r := chi.NewRouter()
	// Inject the test principal before routing so Enforce can read it.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
		})
	})
	r.Route("/v1", func(r chi.Router) {
		r.Use(Enforce(c, perms))
		r.Post("/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
		r.Get("/users", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		// Unmapped route — must pass through regardless of permissions.
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

func TestEnforce_NonUserActorBypasses(t *testing.T) {
	// API-key / service principals carry no RBAC roles → must NOT be checked.
	deny := &fakeChecker{allow: false}
	uid, tid := uuid.New(), uuid.New()
	apiKey := &httpx.Principal{UserID: &uid, TenantID: &tid, ActorType: "api_key"}
	if got := do(buildRouter(deny, apiKey), "POST", "/v1/users"); got != http.StatusCreated {
		t.Fatalf("api_key POST /v1/users = %d, want 201 (bypass)", got)
	}
	if deny.calls != 0 {
		t.Fatalf("checker called %d times for api_key; want 0", deny.calls)
	}
}

func TestEnforce_UnmappedRoutePasses(t *testing.T) {
	deny := &fakeChecker{allow: false}
	if got := do(buildRouter(deny, userPrincipal()), "DELETE", "/v1/things/abc"); got != http.StatusNoContent {
		t.Fatalf("unmapped route = %d, want 204 (pass-through)", got)
	}
	if deny.calls != 0 {
		t.Fatalf("checker called for unmapped route; want 0")
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
