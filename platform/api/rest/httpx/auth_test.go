package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
)

// TestEnforceTenantScope locks in the central cross-tenant guard (QID-18): a
// request to /tenants/{tenantID}/... must be rejected with 403 unless the path
// tenant equals the caller's own tenant; routes without a {tenantID} param pass
// through. Uses a real chi router so the {tenantID} param is actually extracted
// the same way it is in production (the guard reads chi.URLParam).
func TestEnforceTenantScope(t *testing.T) {
	callerTenant := uuid.New()
	otherTenant := uuid.New()
	uid := uuid.New()

	// Mirror the production router structure exactly (nested Route + Group with
	// the guard as group middleware) — chi only populates {tenantID} for a
	// group-level middleware when routes are matched by a nested subrouter, so a
	// flat mux would not exercise the same code path the server uses.
	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						p := &httpx.Principal{UserID: &uid, TenantID: &callerTenant}
						next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
					})
				})
				r.Use(httpx.EnforceTenantScope)
				ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
				r.Get("/tenants/{tenantID}/roles", ok)
				r.Get("/users/{id}", ok) // no tenantID param — must pass through
			})
		})
		return r
	}

	cases := []struct {
		name string
		path string
		want int
	}{
		{"own tenant allowed", "/v1/tenants/" + callerTenant.String() + "/roles", http.StatusOK},
		{"cross tenant forbidden", "/v1/tenants/" + otherTenant.String() + "/roles", http.StatusForbidden},
		{"malformed tenant rejected", "/v1/tenants/not-a-uuid/roles", http.StatusBadRequest},
		{"no tenant param passes through", "/v1/users/" + uuid.New().String(), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newRouter().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("%s: got %d, want %d", tc.path, w.Code, tc.want)
			}
		})
	}
}

func TestRequireTenant(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"tenant present", &httpx.Principal{UserID: &uid, TenantID: &tid}, tid, false},
		{"tenant-less principal", &httpx.Principal{UserID: &uid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireTenant(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got tenant %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}

func TestRequireUser(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"user present", &httpx.Principal{UserID: &uid, TenantID: &tid}, uid, false},
		{"user-less principal", &httpx.Principal{TenantID: &tid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireUser(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got user %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}
