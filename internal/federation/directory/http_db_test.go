//go:build integration

package directory

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestConnectionHandlerRequiresMatchingPrincipalOrganization(test *testing.T) {
	ownOrganization := uuid.New()
	otherOrganization := uuid.New()
	cases := []struct {
		name      string
		principal *uuid.UUID
		path      string
		want      int
	}{
		{name: "anonymous", path: ownOrganization.String(), want: http.StatusUnauthorized},
		{name: "foreign path", principal: &ownOrganization, path: otherOrganization.String(), want: http.StatusForbidden},
		{name: "invalid path", principal: &ownOrganization, path: "invalid", want: http.StatusBadRequest},
		{name: "own organization", principal: &ownOrganization, path: ownOrganization.String(), want: http.StatusOK},
	}
	pool := dbtest.Pool(test)
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			scimSource := &scimFixture{config: &scim.ConfigView{}}
			ldapSource := &ldapFixture{}
			handler := &Handler{Service: newService(test, pool, scimSource, ldapSource)}
			router := chi.NewRouter()
			handler.Mount(router)
			request := httptest.NewRequest(http.MethodGet, "/organizations/"+scenario.path+"/directory/connections?organization_id="+otherOrganization.String(), nil)
			if scenario.principal != nil {
				request = request.WithContext(httpx.WithPrincipal(request.Context(), &httpx.Principal{
					ActorType: "user", OrganizationID: scenario.principal,
				}))
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != scenario.want {
				test.Fatalf("got %d, want %d: %s", response.Code, scenario.want, response.Body.String())
			}
			if scenario.want != http.StatusOK {
				if len(scimSource.organizations) != 0 || len(ldapSource.organizations) != 0 {
					test.Fatal("denied request reached a data source")
				}
				return
			}
			if len(scimSource.organizations) != 1 || scimSource.organizations[0] != ownOrganization || ldapSource.organizations[0] != ownOrganization {
				test.Fatal("organization scope did not come from the principal")
			}
			if strings.TrimSpace(response.Body.String()) != `{"items":[]}` {
				test.Fatalf("empty connections must be an array: %s", response.Body.String())
			}
		})
	}
}
