//go:build integration

package directory

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func TestEventStoreOrganizationIsolationAndAlerts(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, foreignOrganization, userID := uuid.New(), uuid.New(), uuid.New()
	for _, organization := range []uuid.UUID{organizationID, foreignOrganization} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Directory test')`, organization, organization.String()); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.users(id,organization_id,email,status) VALUES($1,$2,$3,'active')`, userID, organizationID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{})
	if _, err := pool.Exec(ctx, `INSERT INTO organization.directory_alerts(id,organization_id,user_id,name,threshold) VALUES($1,$2,$3,'Directory failures',1)`, uuid.New(), organizationID, userID); err != nil {
		test.Fatal(err)
	}
	started := time.Now().Add(-time.Minute)
	for _, status := range []int{201, 409, 502} {
		if err := service.RecordOperation(ctx, organizationID, "scim:"+organizationID.String(), "post", "user", "", status, started, 1500*time.Millisecond); err != nil {
			test.Fatal(err)
		}
	}
	if err := service.RecordOperation(ctx, foreignOrganization, "scim:"+foreignOrganization.String(), "post", "user", "", 201, started, time.Second); err != nil {
		test.Fatal(err)
	}
	page, err := service.Events(ctx, organizationID, eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25})
	if err != nil {
		test.Fatal(err)
	}
	if page.Total != 3 || page.Summary.Successful != 1 || page.Summary.Failed != 2 || len(page.Volume) != 1 || page.Volume[0].Users != 1 {
		test.Fatalf("incorrect scoped summary: %+v", page)
	}
	var notifications int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.notifications WHERE organization_id=$1 AND user_id=$2`, organizationID, userID).Scan(&notifications); err != nil {
		test.Fatal(err)
	}
	if notifications != 1 {
		test.Fatalf("alert throttle produced %d notifications, want 1", notifications)
	}
	filter := eventFilter{Since: time.Now().Add(-time.Hour), Status: "failed", Limit: 1}
	first, err := service.Events(ctx, organizationID, filter)
	if err != nil || first.Total != 2 || len(first.Items) != 1 || first.NextCursor == "" {
		test.Fatalf("first page: %+v %v", first, err)
	}
	if filter.After, err = paging.ParseCursor(url.Values{"cursor": {first.NextCursor}}); err != nil {
		test.Fatal(err)
	}
	page, err = service.Events(ctx, organizationID, filter)
	if err != nil || page.Total != 2 || len(page.Items) != 1 || page.Items[0].ID == first.Items[0].ID || page.NextCursor != "" {
		test.Fatalf("second page: %+v %v; want the other failed event and no further page", page, err)
	}
	connections, err := service.List(ctx, organizationID)
	if err != nil {
		test.Fatal(err)
	}
	if len(connections) != 1 || connections[0].LastSyncAt == nil {
		test.Fatalf("missing successful sync metadata: %+v", connections)
	}

	errorsPage, err := service.Errors(ctx, organizationID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25}})
	if err != nil || errorsPage.Total != 2 || errorsPage.Summary.Open != 2 || errorsPage.Summary.ImpactedUsers != nil {
		test.Fatalf("incorrect error summary: %+v %v", errorsPage, err)
	}
	tester := &ldapFixture{}
	service.ldap = tester
	checkID := uuid.New()
	if err := service.RecordOperation(ctx, organizationID, checkID.String(), "test", "connection", "", 502, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	errorsPage, err = service.Errors(ctx, organizationID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), ConnectionID: checkID.String(), Limit: 25}})
	if err != nil || len(errorsPage.Items) != 1 {
		test.Fatalf("missing failed check: %+v %v", errorsPage, err)
	}
	handler := &Handler{Service: service}
	router := chi.NewRouter()
	handler.Mount(router)
	call := func(organization uuid.UUID, id uuid.UUID, action string) int {
		request := httptest.NewRequest(http.MethodPost, "/organizations/"+organization.String()+"/directory/errors/"+id.String()+"/"+action, nil)
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &userID, OrganizationID: &organization}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response.Code
	}
	eventID := errorsPage.Items[0].ID
	if got := call(foreignOrganization, eventID, "retry"); got != http.StatusNotFound {
		test.Fatalf("foreign error retry status=%d", got)
	}
	if tester.tests != 0 {
		test.Fatal("foreign error reached LDAP")
	}
	if got := call(organizationID, eventID, "retry"); got != http.StatusOK {
		test.Fatalf("retry status=%d", got)
	}
	if got := call(organizationID, eventID, "retry"); got != http.StatusConflict {
		test.Fatalf("repeat retry status=%d", got)
	}
	if tester.tests != 1 {
		test.Fatalf("replayed LDAP test %d times", tester.tests)
	}
	errorsPage, err = service.Errors(ctx, organizationID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), ConnectionID: checkID.String(), Limit: 25}})
	if err != nil || errorsPage.Summary.Retried != 1 || errorsPage.Items[0].Resolution != "retried" {
		test.Fatalf("retry not persisted: %+v %v", errorsPage, err)
	}
}

// TestRefusedSignInIsNotASyncError checks that a person's refused LDAP
// password is recorded as a warning in Sync activity, never an open sync
// error or an alert, while the service account being refused still is both.
func TestRefusedSignInIsNotASyncError(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, userID, connection := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Directory test')`, organizationID, organizationID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.users(id,organization_id,email,status) VALUES($1,$2,$3,'active')`, userID, organizationID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.directory_alerts(id,organization_id,user_id,name,threshold) VALUES($1,$2,$3,'Directory failures',1)`, uuid.New(), organizationID, userID); err != nil {
		test.Fatal(err)
	}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	notifications := func() int {
		return dbtest.Count(test, `SELECT count(*) FROM auth.notifications WHERE organization_id=$1 AND user_id=$2`, organizationID, userID)
	}
	since := eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25}

	if err := service.RecordOperation(ctx, organizationID, connection.String(), "sign-in", "user", "", http.StatusUnauthorized, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	page, err := service.Events(ctx, organizationID, since)
	if err != nil || page.Total != 1 || page.Summary.Warnings != 1 || page.Summary.Failed != 0 {
		test.Fatalf("a refused password in Sync activity: %+v %v, want one warning", page.Summary, err)
	}
	errorsPage, err := service.Errors(ctx, organizationID, errorFilter{eventFilter: since})
	if err != nil || errorsPage.Total != 0 || notifications() != 0 {
		test.Fatalf("a refused password: %d sync errors, %d alerts (%v); want none", errorsPage.Total, notifications(), err)
	}

	if err := service.RecordOperation(ctx, organizationID, connection.String(), "sign-in", "user", "", http.StatusForbidden, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	errorsPage, err = service.Errors(ctx, organizationID, errorFilter{eventFilter: since})
	if err != nil || errorsPage.Total != 1 || errorsPage.Summary.Critical != 1 || notifications() != 1 {
		test.Fatalf("the service account refused: %+v, %d alerts (%v); want one critical error and an alert", errorsPage.Summary, notifications(), err)
	}
	if err := service.RecordLDAPOperation(ctx, ldap.Operation{OrganizationID: organizationID, ConnectionID: connection, Operation: "sign-in", Resource: "user",
		Status: http.StatusBadGateway, Started: time.Now(), Duration: time.Second, Reason: "ldap.dial_failed",
		Params: map[string]string{"host": "ldap.example.test:636"}, Subject: "asha", UserID: &userID}); err != nil {
		test.Fatal(err)
	}
	errorsPage, err = service.Errors(ctx, organizationID, errorFilter{eventFilter: eventFilter{Since: since.Since, Limit: 25, Search: "dial_failed"}})
	if err != nil || errorsPage.Total != 1 {
		test.Fatalf("errors searched by their reason: %+v %v; want the unreachable directory", errorsPage, err)
	}
	if got := errorsPage.Items[0]; got.Reason != "ldap.dial_failed" || got.Params["host"] != "ldap.example.test:636" || got.Subject != "asha" || got.UserID == nil || *got.UserID != userID {
		test.Errorf("an unreachable directory at sign-in listed as %+v; want its reason, host, login name and person", got)
	}
}

// TestSuccessResolvesTheConnectionsFailures checks that a successful operation
// resolves its connection's open connection and permission failures, by the
// system and audited, and leaves other kinds and other connections open.
func TestSuccessResolvesTheConnectionsFailures(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Directory test')`, organizationID, organizationID.String()); err != nil {
		test.Fatal(err)
	}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	connection, other := uuid.New().String(), uuid.New().String()
	record := func(conn, operation string, status int) {
		if err := service.RecordOperation(ctx, organizationID, conn, operation, "connection", "", status, time.Now(), time.Second); err != nil {
			test.Fatal(err)
		}
	}
	record(connection, "test", http.StatusBadGateway)
	record(connection, "test", http.StatusForbidden)
	record(connection, "sync", http.StatusUnprocessableEntity)
	record(other, "test", http.StatusBadGateway)
	open := func(conn string) int {
		return dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id=$1 AND connection_id=$2 AND status='failed' AND resolution='open'`, organizationID, conn)
	}

	record(connection, "test", http.StatusOK)
	if n := open(connection); n != 1 {
		test.Errorf("%d open failures left on the connection, want only the validation one", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id=$1 AND connection_id=$2 AND resolution='resolved' AND resolved_by IS NULL`, organizationID, connection); n != 2 {
		test.Errorf("%d failures resolved by the system, want 2", n)
	}
	if n := open(other); n != 1 {
		test.Errorf("another connection's failure was resolved: %d open, want 1", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE organization_id=$1 AND action='directory.errors_resolved' AND actor_type='system' AND metadata->>'connection_id'=$2`, organizationID, connection); n != 1 {
		test.Errorf("%d audit records of the resolution, want 1", n)
	}
	record(connection, "test", http.StatusOK)
	if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE organization_id=$1 AND action='directory.errors_resolved'`, organizationID); n != 1 {
		test.Errorf("a success with nothing to resolve was audited: %d records, want 1", n)
	}
}

// TestDirectorySearchTakesWildcardsLiterally checks that _ and % in an event or
// error search match only themselves.
func TestDirectorySearchTakesWildcardsLiterally(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID := dbtest.Organization(test)
	for _, message := range []string{"qa_b refused", "qaXb refused", "100% refused", "plain refused"} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.directory_events (id, organization_id, connection_id, operation, trigger_type, resource_type, started_at, duration_ms, http_status, status, message)
			VALUES ($1, $2, 'scim', 'post', 'push', 'user', NOW(), 1, 502, 'failed', $3)`, uuid.New(), organizationID, message); err != nil {
			test.Fatal(err)
		}
	}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{})
	for search, want := range map[string]string{"qa_b": "qa_b refused", "%": "100% refused"} {
		filter := eventFilter{Since: time.Now().Add(-time.Hour), Search: search, Limit: 25}
		events, err := service.Events(ctx, organizationID, filter)
		if err != nil {
			test.Fatal(err)
		}
		if len(events.Items) != 1 || events.Items[0].Message != want {
			test.Errorf("events matching %q: %d, want only %q", search, len(events.Items), want)
		}
		failures, err := service.Errors(ctx, organizationID, errorFilter{eventFilter: filter})
		if err != nil {
			test.Fatal(err)
		}
		if len(failures.Items) != 1 || failures.Items[0].Message != want {
			test.Errorf("errors matching %q: %d, want only %q", search, len(failures.Items), want)
		}
	}
}

// TestScheduledSyncEvents checks how an LDAP connection's scheduled syncs are
// recorded, resolved and shown.
func TestScheduledSyncEvents(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID := dbtest.Organization(test)
	connection := uuid.New()
	ldapSource := &ldapFixture{records: []ldap.Connection{{ID: connection, OrganizationID: organizationID, Name: "Head office", Status: "active"}}}
	service := newService(test, pool, &scimFixture{config: &scim.ConfigView{}}, ldapSource)
	record := func(status int, reason string, at time.Time) {
		test.Helper()
		if err := service.RecordLDAPOperation(ctx, ldap.Operation{OrganizationID: organizationID, ConnectionID: connection, Operation: "sync",
			Resource: "connection", Status: status, Started: at, Duration: time.Second, Reason: reason}); err != nil {
			test.Fatal(err)
		}
	}
	stopped := time.Now().Add(-10 * time.Minute)
	record(http.StatusPreconditionFailed, ldap.CodeSyncEmptyResult, stopped)
	open := func() int {
		return dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id = $1 AND connection_id = $2
			AND status = 'failed' AND resolution = 'open'`, organizationID, connection.String())
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM organization.directory_events WHERE organization_id = $1 AND trigger_type = 'scheduled'
		AND category = 'provisioning' AND severity = 'critical'`, organizationID); n != 1 || open() != 1 {
		test.Fatalf("a stopped sync: %d scheduled critical events, %d open; want 1 and 1", n, open())
	}
	synced := time.Now().Add(-time.Minute)
	record(http.StatusOK, "", synced)
	if open() != 0 {
		test.Error("a successful sync left the stopped one open")
	}
	records, err := service.List(ctx, organizationID)
	if err != nil {
		test.Fatal(err)
	}
	if len(records) != 1 || records[0].LastSyncAt == nil || records[0].LastSyncAt.Sub(synced).Abs() > time.Second ||
		records[0].Health != "healthy" || records[0].Scope != "users-and-groups" {
		test.Fatalf("connection %+v; want healthy, last synced by the scheduled sync, people and groups in scope", records)
	}
}
