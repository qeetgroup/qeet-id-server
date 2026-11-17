package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestOrganizationRoutesAreScoped checks that row-level security scopes the
// organization-administration routes to the caller's organization, and leaves a
// person's own routes, which act across their organizations, unscoped.
func TestOrganizationRoutesAreScoped(t *testing.T) {
	organization, user := uuid.New(), uuid.New()
	var scoped bool
	var scopedTo uuid.UUID
	h := scopeOrganizationRoutes(RoutePolicies())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		scopedTo, scoped = postgres.ScopedTo(r.Context())
	}))
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/v1/users", true},
		{http.MethodGet, "/v1/tenants/" + organization.String() + "/webhooks", true},
		{http.MethodPatch, "/v1/tenants/" + organization.String(), true},
		{http.MethodPost, "/v1/auth/switch-tenant", false},
		{http.MethodPost, "/v1/auth/password", false},
		{http.MethodGet, "/v1/me/organizations", false},
		{http.MethodPost, "/v1/me/invites/" + uuid.NewString() + "/accept", false},
		{http.MethodDelete, "/v1/passkeys/" + uuid.NewString(), false},
		{http.MethodPost, "/v1/tenants", false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &user, OrganizationID: &organization}))
		h.ServeHTTP(httptest.NewRecorder(), r)
		if scoped != tc.want || (scoped && scopedTo != organization) {
			t.Errorf("%s %s: scoped %v to %s, want scoped %v", tc.method, tc.path, scoped, scopedTo, tc.want)
		}
	}
}
