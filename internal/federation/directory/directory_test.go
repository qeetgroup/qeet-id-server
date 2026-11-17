package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

type scimFixture struct {
	config        *scim.ConfigView
	organizations []uuid.UUID
}

func (source *scimFixture) Config(_ context.Context, organizationID uuid.UUID) (*scim.ConfigView, error) {
	source.organizations = append(source.organizations, organizationID)
	return source.config, nil
}

type ldapFixture struct {
	records       []ldap.Connection
	organizations []uuid.UUID
	tests         int
	testError     error
}

func (source *ldapFixture) TestConnection(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
	source.tests++
	return source.testError
}

func (source *ldapFixture) List(_ context.Context, organizationID uuid.UUID) ([]ldap.Connection, error) {
	source.organizations = append(source.organizations, organizationID)
	return source.records, nil
}

func TestConnectionSnapshotDoesNotInventHealthOrExposeCredentials(test *testing.T) {
	organizationID := uuid.New()
	usedAt := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	scimSource := &scimFixture{config: &scim.ConfigView{
		TokenSet: true, TokenPrefix: "private-prefix", LastUsedAt: &usedAt, ProvisionedCount: 128,
	}}
	ldapSource := &ldapFixture{records: []ldap.Connection{{
		ID: uuid.New(), OrganizationID: organizationID, Name: "Corporate directory", Status: "active",
		ServerURL: "ldaps://directory.example.test", BindDN: "private-bind-dn", LastLoginAt: &usedAt,
	}}}
	records, err := NewService(scimSource, ldapSource).List(context.Background(), organizationID)
	if err != nil {
		test.Fatal(err)
	}
	if len(records) != 2 {
		test.Fatalf("got %d connections, want 2", len(records))
	}
	for _, record := range records {
		if record.Health != "unknown" || record.LastSyncAt != nil || record.Environment != nil {
			test.Fatalf("configuration was presented as sync telemetry: %+v", record)
		}
		if record.LastActivityAt == nil || !record.LastActivityAt.Equal(usedAt) {
			test.Fatal("last activity was not retained")
		}
	}
	raw, err := json.Marshal(records)
	if err != nil {
		test.Fatal(err)
	}
	for _, prohibited := range []string{"private-prefix", "private-bind-dn", "bind_password", "token_prefix"} {
		if strings.Contains(string(raw), prohibited) {
			test.Fatalf("connection snapshot exposed %q", prohibited)
		}
	}
}

func TestOperationClassificationAndFilterBounds(test *testing.T) {
	for _, status := range []int{200, 201, 204} {
		outcome, _, code, _, _ := classifyOperation("post", status)
		if outcome != "success" || code != "" {
			test.Fatalf("status %d misclassified", status)
		}
	}
	for _, status := range []int{400, 401, 403, 404, 409, 422, 429, 500, 502} {
		outcome, category, code, message, severity := classifyOperation("post", status)
		if outcome != "failed" || category == "" || code == "" || message == "" || severity == "" {
			test.Fatalf("status %d lacks safe error metadata", status)
		}
	}
	// At sign-in a person's refused credentials are a warning; the directory
	// itself refusing (403) or failing stays an error.
	if outcome, category, _, _, severity := classifyOperation("sign-in", 401); outcome != "warning" || category != "credentials" || severity != "" {
		test.Fatalf("a refused sign-in classified %s/%s/%s, want a warning without severity", outcome, category, severity)
	}
	for _, status := range []int{403, 502} {
		if outcome, _, _, _, severity := classifyOperation("sign-in", status); outcome != "failed" || severity != "critical" {
			test.Fatalf("sign-in status %d classified %s/%s, want a critical failure", status, outcome, severity)
		}
	}
	for _, query := range []string{"days=0", "days=91", "limit=0", "limit=101", "cursor=not-a-cursor", "status=invalid"} {
		if _, err := parseEventFilter(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err == nil {
			test.Fatalf("accepted invalid filter %s", query)
		}
	}
	at, id := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC), uuid.New()
	filter, err := parseEventFilter(httptest.NewRequest(http.MethodGet, "/?days=30&limit=50&cursor="+paging.EncodeTimeUUID(at, id)+"&status=failed", nil))
	if err != nil || filter.Limit != 50 || !filter.After.Set || !filter.After.Time.Equal(at) || filter.After.ID != id || filter.Status != "failed" {
		test.Fatalf("invalid parsed filter: %+v %v", filter, err)
	}
}

func TestRetryEligibilityNeverReplaysProviderRequestsOrCredentials(test *testing.T) {
	base := Event{Status: "failed", Resolution: "open", Operation: "test", ConnectionID: uuid.New().String()}
	if !canRetry(base) {
		test.Fatal("failed LDAP connection test must be retryable")
	}
	for _, operation := range []string{"sign-in", "post", "put", "patch", "delete"} {
		event := base
		event.Operation = operation
		if canRetry(event) {
			test.Fatalf("operation %s must not be replayed", operation)
		}
	}
	base.ConnectionID = "scim:" + uuid.New().String()
	if canRetry(base) {
		test.Fatal("SCIM source requests cannot be replayed by the console")
	}
	base.ConnectionID = uuid.New().String()
	base.Resolution = "retried"
	if canRetry(base) {
		test.Fatal("completed retry must not repeat")
	}
}

func TestConnectionSourcesCannotReturnAnotherOrganization(test *testing.T) {
	scimSource := &scimFixture{config: &scim.ConfigView{}}
	ldapSource := &ldapFixture{records: []ldap.Connection{{ID: uuid.New(), OrganizationID: uuid.New()}}}
	if records, err := NewService(scimSource, ldapSource).List(context.Background(), uuid.New()); err == nil || records != nil {
		test.Fatal("cross-tenant source result was not rejected")
	}
}

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
		{name: "own tenant", principal: &ownOrganization, path: ownOrganization.String(), want: http.StatusOK},
	}
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			scimSource := &scimFixture{config: &scim.ConfigView{}}
			ldapSource := &ldapFixture{}
			handler := &Handler{Service: NewService(scimSource, ldapSource)}
			router := chi.NewRouter()
			handler.Mount(router)
			request := httptest.NewRequest(http.MethodGet, "/tenants/"+scenario.path+"/directory/connections?tenant_id="+otherOrganization.String(), nil)
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
				test.Fatal("tenant scope did not come from the principal")
			}
			if strings.TrimSpace(response.Body.String()) != `{"items":[]}` {
				test.Fatalf("empty connections must be an array: %s", response.Body.String())
			}
		})
	}
}
