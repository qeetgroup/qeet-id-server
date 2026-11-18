//go:build integration

package directory

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// recordingTester checks a connection as the LDAP service does: it records the
// check as an operation, within two seconds, carrying the retried error.
type recordingTester struct{ service *Service }

func (r *recordingTester) TestConnection(ctx context.Context, organizationID, connectionID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.service.RecordOperation(ctx, organizationID, connectionID.String(), "test", "connection", "", http.StatusOK, time.Now(), time.Second)
}

func (*recordingTester) List(context.Context, uuid.UUID) ([]ldap.Connection, error) { return nil, nil }

// TestRetryRecordsItsOwnCheck checks that retrying a failed connection check
// records the new check, pointing back at the error, and marks the error
// retried: the error's row isn't held while the check runs.
func TestRetryRecordsItsOwnCheck(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, userID, connection := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Directory test')`, organizationID, organizationID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.users(id,organization_id,email,status) VALUES($1,$2,$3,'active')`, userID, organizationID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	service.ldap = &recordingTester{service: service}
	if err := service.RecordOperation(ctx, organizationID, connection.String(), "test", "connection", "", http.StatusBadGateway, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	var failed uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organization.directory_events WHERE organization_id=$1 AND status='failed'`, organizationID).Scan(&failed); err != nil {
		test.Fatal(err)
	}

	router := chi.NewRouter()
	(&Handler{Service: service}).Mount(router)
	request := httptest.NewRequest(http.MethodPost, "/organizations/"+organizationID.String()+"/directory/errors/"+failed.String()+"/retry", nil)
	request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &userID, OrganizationID: &organizationID}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"succeeded":true`) {
		test.Fatalf("retry: %d %s, want the check to succeed", response.Code, response.Body.String())
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id=$1 AND retry_of=$2 AND status='success'`, organizationID, failed); n != 1 {
		test.Errorf("%d checks recorded for the retry, want 1", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id=$1 AND id=$2 AND resolution='retried'`, organizationID, failed); n != 1 {
		test.Error("the failure was not marked retried")
	}
}
