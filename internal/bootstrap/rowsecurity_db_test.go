//go:build integration

package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestOrganizationRoutesAreScoped checks that row-level security scopes the
// organization-administration routes to the caller's organization, and leaves a
// person's own routes, which act across their organizations, unscoped: the
// handler's queries run with the organization set on their connection, or none.
func TestOrganizationRoutesAreScoped(t *testing.T) {
	pool := dbtest.Pool(t)
	organization, user := uuid.New(), uuid.New()
	var setting string
	h := scopeOrganizationRoutes(RoutePolicies())(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if err := pool.QueryRow(r.Context(), `SELECT coalesce(current_setting('qeet.organization_id', true), '')`).Scan(&setting); err != nil {
			t.Error(err)
		}
	}))
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/v1/users", true},
		{http.MethodGet, "/v1/organizations/" + organization.String() + "/webhooks", true},
		{http.MethodPatch, "/v1/organizations/" + organization.String(), true},
		{http.MethodPost, "/v1/auth/switch-organization", false},
		{http.MethodPost, "/v1/auth/password", false},
		{http.MethodGet, "/v1/me/organizations", false},
		{http.MethodPost, "/v1/me/invites/" + uuid.NewString() + "/accept", false},
		{http.MethodDelete, "/v1/passkeys/" + uuid.NewString(), false},
		{http.MethodPost, "/v1/organizations", false},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &user, OrganizationID: &organization}))
		setting = "unread"
		h.ServeHTTP(httptest.NewRecorder(), r)
		if scoped := setting != ""; scoped != tc.want || (scoped && setting != organization.String()) {
			t.Errorf("%s %s: scoped to %q, want scoped %v", tc.method, tc.path, setting, tc.want)
		}
	}
}
