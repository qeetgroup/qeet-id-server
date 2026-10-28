//go:build integration

package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

func TestDirectoryMigrationsRoundTrip(test *testing.T) {
	pool := dbtest.Owner(test)
	ctx := dbtest.Context(test)
	_, source, _, _ := runtime.Caller(0)
	directory := filepath.Join(filepath.Dir(source), "..", "..", "platform", "database", "migrations")
	for _, migration := range []string{
		"0111_suspension_review.down.sql",
		"0110_directory_mappings.down.sql",
		"0109_directory_events.down.sql",
		"0109_directory_events.up.sql",
		"0110_directory_mappings.up.sql",
		"0111_suspension_review.up.sql",
	} {
		script, err := os.ReadFile(filepath.Join(directory, migration))
		if err != nil {
			test.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(script)); err != nil {
			test.Fatalf("migration %s: %v", migration, err)
		}
	}
	for _, table := range []string{"directory_events", "directory_alerts", "directory_mappings", "directory_profiles"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('tenant.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil || !exists {
			test.Fatalf("table %s was not restored: %v", table, err)
		}
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema='user' AND table_name='users' AND column_name IN ('suspended_at','suspension_reason','suspension_source','suspension_risk','suspension_review')`).Scan(&columns); err != nil || columns != 5 {
		test.Fatalf("suspension columns were not restored: count=%d err=%v", columns, err)
	}
}

func TestEventStoreTenantIsolationAndAlerts(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, foreignTenant, userID := uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{tenantID, foreignTenant} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Directory test')`, tenant, tenant.String()); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".users(id,tenant_id,email,status) VALUES($1,$2,$3,'active')`, userID, tenantID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	service := NewService(&scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{})
	service.SetEventStore(pool)
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.directory_alerts(id,tenant_id,user_id,name,threshold) VALUES($1,$2,$3,'Directory failures',1)`, uuid.New(), tenantID, userID); err != nil {
		test.Fatal(err)
	}
	started := time.Now().Add(-time.Minute)
	for _, status := range []int{201, 409, 502} {
		if err := service.RecordOperation(ctx, tenantID, "scim:"+tenantID.String(), "post", "user", "", status, started, 1500*time.Millisecond); err != nil {
			test.Fatal(err)
		}
	}
	if err := service.RecordOperation(ctx, foreignTenant, "scim:"+foreignTenant.String(), "post", "user", "", 201, started, time.Second); err != nil {
		test.Fatal(err)
	}
	page, err := service.Events(ctx, tenantID, eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25})
	if err != nil {
		test.Fatal(err)
	}
	if page.Total != 3 || page.Summary.Successful != 1 || page.Summary.Failed != 2 || len(page.Volume) != 1 || page.Volume[0].Users != 1 {
		test.Fatalf("incorrect scoped summary: %+v", page)
	}
	var notifications int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.notifications WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID).Scan(&notifications); err != nil {
		test.Fatal(err)
	}
	if notifications != 1 {
		test.Fatalf("alert throttle produced %d notifications, want 1", notifications)
	}
	filter := eventFilter{Since: time.Now().Add(-time.Hour), Status: "failed", Limit: 1, Offset: 1}
	page, err = service.Events(ctx, tenantID, filter)
	if err != nil || page.Total != 2 || len(page.Items) != 1 {
		test.Fatalf("pagination/filter mismatch: %+v %v", page, err)
	}
	connections, err := service.List(ctx, tenantID)
	if err != nil {
		test.Fatal(err)
	}
	if len(connections) != 1 || connections[0].LastSyncAt == nil {
		test.Fatalf("missing successful sync metadata: %+v", connections)
	}

	errorsPage, err := service.Errors(ctx, tenantID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25}})
	if err != nil || errorsPage.Total != 2 || errorsPage.Summary.Open != 2 || errorsPage.Summary.ImpactedUsers != nil {
		test.Fatalf("incorrect error summary: %+v %v", errorsPage, err)
	}
	tester := &ldapFixture{}
	service.ldap = tester
	checkID := uuid.New()
	if err := service.RecordOperation(ctx, tenantID, checkID.String(), "test", "connection", "", 502, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	errorsPage, err = service.Errors(ctx, tenantID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), ConnectionID: checkID.String(), Limit: 25}})
	if err != nil || len(errorsPage.Items) != 1 {
		test.Fatalf("missing failed check: %+v %v", errorsPage, err)
	}
	handler := &Handler{Service: service}
	router := chi.NewRouter()
	handler.Mount(router)
	call := func(tenant uuid.UUID, id uuid.UUID, action string) int {
		request := httptest.NewRequest(http.MethodPost, "/tenants/"+tenant.String()+"/directory/errors/"+id.String()+"/"+action, nil)
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &userID, TenantID: &tenant}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response.Code
	}
	eventID := errorsPage.Items[0].ID
	if got := call(foreignTenant, eventID, "retry"); got != http.StatusNotFound {
		test.Fatalf("foreign error retry status=%d", got)
	}
	if tester.tests != 0 {
		test.Fatal("foreign error reached LDAP")
	}
	if got := call(tenantID, eventID, "retry"); got != http.StatusOK {
		test.Fatalf("retry status=%d", got)
	}
	if got := call(tenantID, eventID, "retry"); got != http.StatusConflict {
		test.Fatalf("repeat retry status=%d", got)
	}
	if tester.tests != 1 {
		test.Fatalf("replayed LDAP test %d times", tester.tests)
	}
	errorsPage, err = service.Errors(ctx, tenantID, errorFilter{eventFilter: eventFilter{Since: time.Now().Add(-time.Hour), ConnectionID: checkID.String(), Limit: 25}})
	if err != nil || errorsPage.Summary.Retried != 1 || errorsPage.Items[0].Resolution != "retried" {
		test.Fatalf("retry not persisted: %+v %v", errorsPage, err)
	}
}

func TestSavedMappingAppliesToSCIMAndRejectsStaleOrForeignWrites(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, actorID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Mapping test')`, tenantID, tenantID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".users(id,tenant_id,email,status) VALUES($1,$2,$3,'active')`, actorID, tenantID, actorID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	scimService := scim.NewService(pool, user.NewRepository(pool))
	service := NewService(scimService, &ldapFixture{})
	service.SetEventStore(pool)
	scimService.SetProfileMapper(service)
	tx, err := pool.Begin(ctx)
	if err != nil {
		test.Fatal(err)
	}
	token, err := scimService.Rotate(ctx, tx, tenantID)
	if err != nil {
		test.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		test.Fatal(err)
	}
	router := chi.NewRouter()
	(&Handler{Service: service}).Mount(router)
	connectionID := "scim:" + tenantID.String()
	base := "/tenants/" + tenantID.String() + "/directory/connections/" + connectionID + "/mappings"
	call := func(method, path string, body any, principalTenant uuid.UUID) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &actorID, TenantID: &principalTenant}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	rule := Mapping{Source: "department", Target: "department", ValueType: "string", Transform: "uppercase", Enabled: true}
	created := call(http.MethodPost, base, rule, tenantID)
	if created.Code != http.StatusCreated {
		test.Fatalf("create mapping: %d %s", created.Code, created.Body.String())
	}
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil {
		test.Fatal(err)
	}
	preview := call(http.MethodPost, base+"/preview", map[string]any{"source": map[string]any{"department": "engineering"}}, tenantID)
	var mapped MappingPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &mapped); err != nil || !mapped.Valid || mapped.Profile["department"] != "ENGINEERING" {
		test.Fatalf("preview mismatch: %s %v", preview.Body.String(), err)
	}
	if response := call(http.MethodPut, base+"/"+rule.ID.String(), rule, uuid.New()); response.Code != http.StatusForbidden {
		test.Fatalf("foreign write accepted: %d", response.Code)
	}
	updated := call(http.MethodPut, base+"/"+rule.ID.String(), rule, tenantID)
	if updated.Code != http.StatusOK {
		test.Fatalf("update mapping: %s", updated.Body.String())
	}
	if response := call(http.MethodPut, base+"/"+rule.ID.String(), rule, tenantID); response.Code != http.StatusConflict {
		test.Fatalf("stale update accepted: %d", response.Code)
	}
	protocol := chi.NewRouter()
	(&scim.Handler{Service: scimService}).MountPublic(protocol)
	raw, _ := json.Marshal(map[string]any{"userName": uuid.New().String() + "@example.test", "displayName": "Mapping User", "department": "engineering"})
	request := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/scim+json")
	response := httptest.NewRecorder()
	protocol.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		test.Fatalf("mapped provisioning failed: %d %s", response.Code, response.Body.String())
	}
	var resource struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &resource); err != nil {
		test.Fatal(err)
	}
	var department string
	if err := pool.QueryRow(ctx, `SELECT profile->>'department' FROM tenant.directory_profiles WHERE tenant_id=$1 AND user_id=$2 AND connection_id=$3`, tenantID, resource.ID, connectionID).Scan(&department); err != nil || department != "ENGINEERING" {
		test.Fatalf("preview and persisted profile diverged: %q %v", department, err)
	}
	foreignMappings, err := service.Mappings(ctx, uuid.New(), uuid.New().String())
	if err != nil || len(foreignMappings) != 0 {
		test.Fatalf("foreign mappings visible: %+v %v", foreignMappings, err)
	}
}

func TestSuspendedDirectoryPrivacyReviewAndReactivation(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, foreignTenant, actorID, ownedID, foreignID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{tenantID, foreignTenant} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Suspension test')`, tenant, tenant.String()); err != nil {
			test.Fatal(err)
		}
	}
	for _, record := range []struct {
		id, tenant uuid.UUID
		status     string
	}{{actorID, tenantID, "active"}, {ownedID, tenantID, "suspended"}, {foreignID, foreignTenant, "suspended"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO "user".users(id,tenant_id,email,status) VALUES($1,$2,$3,$4)`, record.id, record.tenant, record.id.String()+"@example.test", record.status); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE "user".users SET suspension_risk='high',suspension_reason='account_compromise' WHERE id=$1`, foreignID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.roles(id,tenant_id,name) VALUES($1,$2,'directory-reader')`, roleID, tenantID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.user_roles(user_id,tenant_id,role_id) VALUES($1,$2,$3)`, foreignID, tenantID, roleID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions(user_id,tenant_id) VALUES($1,$2)`, ownedID, tenantID); err != nil {
		test.Fatal(err)
	}
	repository := user.NewRepository(pool)
	page, err := repository.ListSuspended(ctx, tenantID, user.SuspensionFilters{Limit: 25})
	if err != nil || page.Total != 2 || page.Summary.HighRisk != 0 {
		test.Fatalf("suspension scope: %+v %v", page, err)
	}
	for _, record := range page.Items {
		if record.ID == foreignID && (record.CanManage || record.Risk != "unknown" || record.Reason != "managed_elsewhere" || record.SuspendedAt != nil) {
			test.Fatalf("foreign private facts exposed: %+v", record)
		}
	}
	router := chi.NewRouter()
	(&user.Handler{Repo: repository, ActOnCheck: rbac.NewRepository(dbtest.Pool(test)).CheckActOn}).Mount(router)
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &actorID, TenantID: &tenantID}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	selfRequest := httptest.NewRequest(http.MethodPost, "/users/"+ownedID.String()+"/reactivate", nil)
	selfRequest = selfRequest.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &ownedID, TenantID: &tenantID}))
	selfResponse := httptest.NewRecorder()
	router.ServeHTTP(selfResponse, selfRequest)
	if selfResponse.Code != http.StatusForbidden {
		test.Fatalf("self reactivation accepted: %d", selfResponse.Code)
	}
	// foreignID's home is another tenant, so this one may not manage the account.
	if response := call(http.MethodPost, "/users/"+foreignID.String()+"/reactivate", nil); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), errs.CodeUserManagedElsewhere) {
		test.Fatalf("foreign reactivation: %d %s, want 403 %s", response.Code, response.Body.String(), errs.CodeUserManagedElsewhere)
	}
	if response := call(http.MethodPut, "/users/"+ownedID.String()+"/suspension", map[string]string{"reason": "offboarding", "risk": "low", "review": "reviewed"}); response.Code != http.StatusNoContent {
		test.Fatalf("review failed: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/users/"+ownedID.String()+"/reactivate", nil); response.Code != http.StatusOK {
		test.Fatalf("reactivation failed: %d %s", response.Code, response.Body.String())
	}
	if response := call(http.MethodPost, "/users/"+ownedID.String()+"/reactivate", nil); response.Code != http.StatusConflict {
		test.Fatalf("repeat reactivation accepted: %d", response.Code)
	}
	var liveSessions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM auth.sessions WHERE user_id=$1 AND revoked_at IS NULL`, ownedID).Scan(&liveSessions); err != nil || liveSessions != 0 {
		test.Fatalf("old sessions remained active: %d %v", liveSessions, err)
	}
	page, err = repository.ListSuspended(ctx, tenantID, user.SuspensionFilters{Limit: 25})
	if err != nil || page.Total != 1 || page.Items[0].ID != foreignID {
		test.Fatalf("reactivated user remained listed: %+v %v", page, err)
	}
}

// TestRefusedSignInIsNotASyncError checks that a person's refused LDAP
// password is recorded as a warning in Sync activity, never an open sync
// error or an alert, while the service account being refused still is both.
func TestRefusedSignInIsNotASyncError(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, userID, connection := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Directory test')`, tenantID, tenantID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".users(id,tenant_id,email,status) VALUES($1,$2,$3,'active')`, userID, tenantID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.directory_alerts(id,tenant_id,user_id,name,threshold) VALUES($1,$2,$3,'Directory failures',1)`, uuid.New(), tenantID, userID); err != nil {
		test.Fatal(err)
	}
	service := NewService(&scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	service.SetEventStore(pool)
	notifications := func() int {
		return dbtest.Count(test, `SELECT count(*) FROM auth.notifications WHERE tenant_id=$1 AND user_id=$2`, tenantID, userID)
	}
	since := eventFilter{Since: time.Now().Add(-time.Hour), Limit: 25}

	if err := service.RecordOperation(ctx, tenantID, connection.String(), "sign-in", "user", "", http.StatusUnauthorized, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	page, err := service.Events(ctx, tenantID, since)
	if err != nil || page.Total != 1 || page.Summary.Warnings != 1 || page.Summary.Failed != 0 {
		test.Fatalf("a refused password in Sync activity: %+v %v, want one warning", page.Summary, err)
	}
	errorsPage, err := service.Errors(ctx, tenantID, errorFilter{eventFilter: since})
	if err != nil || errorsPage.Total != 0 || notifications() != 0 {
		test.Fatalf("a refused password: %d sync errors, %d alerts (%v); want none", errorsPage.Total, notifications(), err)
	}

	if err := service.RecordOperation(ctx, tenantID, connection.String(), "sign-in", "user", "", http.StatusForbidden, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	errorsPage, err = service.Errors(ctx, tenantID, errorFilter{eventFilter: since})
	if err != nil || errorsPage.Total != 1 || errorsPage.Summary.Critical != 1 || notifications() != 1 {
		test.Fatalf("the service account refused: %+v, %d alerts (%v); want one critical error and an alert", errorsPage.Summary, notifications(), err)
	}
}

// recordingTester checks a connection as the LDAP service does: it records the
// check as an operation, within two seconds, carrying the retried error.
type recordingTester struct{ service *Service }

func (r *recordingTester) TestConnection(ctx context.Context, tenantID, connectionID uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.service.RecordOperation(ctx, tenantID, connectionID.String(), "test", "connection", "", http.StatusOK, time.Now(), time.Second)
}

func (*recordingTester) List(context.Context, uuid.UUID) ([]ldap.Connection, error) { return nil, nil }

// TestRetryRecordsItsOwnCheck checks that retrying a failed connection check
// records the new check, pointing back at the error, and marks the error
// retried: the error's row isn't held while the check runs.
func TestRetryRecordsItsOwnCheck(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, userID, connection := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Directory test')`, tenantID, tenantID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO "user".users(id,tenant_id,email,status) VALUES($1,$2,$3,'active')`, userID, tenantID, userID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	service := NewService(&scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	service.SetEventStore(pool)
	service.ldap = &recordingTester{service: service}
	if err := service.RecordOperation(ctx, tenantID, connection.String(), "test", "connection", "", http.StatusBadGateway, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	var failed uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenant.directory_events WHERE tenant_id=$1 AND status='failed'`, tenantID).Scan(&failed); err != nil {
		test.Fatal(err)
	}

	router := chi.NewRouter()
	(&Handler{Service: service}).Mount(router)
	request := httptest.NewRequest(http.MethodPost, "/tenants/"+tenantID.String()+"/directory/errors/"+failed.String()+"/retry", nil)
	request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &userID, TenantID: &tenantID}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"succeeded":true`) {
		test.Fatalf("retry: %d %s, want the check to succeed", response.Code, response.Body.String())
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND retry_of=$2 AND status='success'`, tenantID, failed); n != 1 {
		test.Errorf("%d checks recorded for the retry, want 1", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND id=$2 AND resolution='retried'`, tenantID, failed); n != 1 {
		test.Error("the failure was not marked retried")
	}
}

// TestSuccessResolvesTheConnectionsFailures checks that a successful operation
// resolves its connection's open connection and permission failures, by the
// system and audited, and leaves other kinds and other connections open.
func TestSuccessResolvesTheConnectionsFailures(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.tenants(id,slug,name) VALUES($1,$2,'Directory test')`, tenantID, tenantID.String()); err != nil {
		test.Fatal(err)
	}
	service := NewService(&scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	service.SetEventStore(pool)
	connection, other := uuid.New().String(), uuid.New().String()
	record := func(conn, operation string, status int) {
		if err := service.RecordOperation(ctx, tenantID, conn, operation, "connection", "", status, time.Now(), time.Second); err != nil {
			test.Fatal(err)
		}
	}
	record(connection, "test", http.StatusBadGateway)
	record(connection, "test", http.StatusForbidden)
	record(connection, "sync", http.StatusUnprocessableEntity)
	record(other, "test", http.StatusBadGateway)
	open := func(conn string) int {
		return dbtest.Count(test, `SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND connection_id=$2 AND status='failed' AND resolution='open'`, tenantID, conn)
	}

	record(connection, "test", http.StatusOK)
	if n := open(connection); n != 1 {
		test.Errorf("%d open failures left on the connection, want only the validation one", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM tenant.directory_events WHERE tenant_id=$1 AND connection_id=$2 AND resolution='resolved' AND resolved_by IS NULL`, tenantID, connection); n != 2 {
		test.Errorf("%d failures resolved by the system, want 2", n)
	}
	if n := open(other); n != 1 {
		test.Errorf("another connection's failure was resolved: %d open, want 1", n)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE tenant_id=$1 AND action='directory.errors_resolved' AND actor_type='system' AND metadata->>'connection_id'=$2`, tenantID, connection); n != 1 {
		test.Errorf("%d audit records of the resolution, want 1", n)
	}
	record(connection, "test", http.StatusOK)
	if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE tenant_id=$1 AND action='directory.errors_resolved'`, tenantID); n != 1 {
		test.Errorf("a success with nothing to resolve was audited: %d records, want 1", n)
	}
}

// TestAlertsCanBeListedChangedPausedAndRemoved checks the directory alert
// routes: a paused alert notifies nobody, changes and removals stay in the
// organisation, and each is audited.
func TestAlertsCanBeListedChangedPausedAndRemoved(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID, other := dbtest.Tenant(test), dbtest.Tenant(test)
	admin, otherAdmin := dbtest.User(test, tenantID, tenantID), dbtest.User(test, other, other)
	service := NewService(&scimFixture{config: &scim.ConfigView{}}, &ldapFixture{})
	service.SetEventStore(pool)
	as := func(user, tenant uuid.UUID) http.Handler {
		return dbtest.Serve(dbtest.Principal(user, tenant), (&Handler{Service: service}).Mount)
	}
	h := as(admin.ID, tenantID)
	base := "/tenants/" + tenantID.String() + "/directory/alerts"
	var alert Alert
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodPost, base, map[string]any{"name": "Any failure", "threshold": 1}), &alert)
	var list struct {
		Items []Alert `json:"items"`
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 1 || list.Items[0].ID != alert.ID || list.Items[0].UserID != admin.ID {
		test.Fatalf("list %+v, want the one alert, for its maker", list.Items)
	}

	if rec := dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"enabled": false}); rec.Code != http.StatusOK {
		test.Fatalf("pause: %d %s", rec.Code, rec.Body.String())
	}
	if err := service.RecordOperation(ctx, tenantID, uuid.NewString(), "test", "connection", "", http.StatusBadGateway, time.Now(), time.Second); err != nil {
		test.Fatal(err)
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM auth.notifications WHERE tenant_id=$1`, tenantID); n != 0 {
		test.Errorf("a paused alert sent %d notifications, want none", n)
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"threshold": 5, "name": "Bursts"}), &alert)
	if alert.Threshold != 5 || alert.Name != "Bursts" || alert.Enabled {
		test.Errorf("after changing: %+v, want threshold 5, renamed, still paused", alert)
	}
	if rec := dbtest.Do(test, h, http.MethodPatch, base+"/"+alert.ID.String(), map[string]any{"connection_id": uuid.NewString()}); rec.Code != http.StatusNotFound {
		test.Errorf("an unknown connection: %d, want 404", rec.Code)
	}
	otherBase := "/tenants/" + other.String() + "/directory/alerts/" + alert.ID.String()
	if rec := dbtest.Do(test, as(otherAdmin.ID, other), http.MethodDelete, otherBase, nil); rec.Code != http.StatusNotFound {
		test.Errorf("another organisation removing the alert: %d, want 404", rec.Code)
	}
	if rec := dbtest.Do(test, h, http.MethodDelete, base+"/"+alert.ID.String(), nil); rec.Code != http.StatusNoContent {
		test.Errorf("remove: %d", rec.Code)
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, base, nil), &list)
	if len(list.Items) != 0 {
		test.Errorf("after removing: %+v, want none", list.Items)
	}
	for action, want := range map[string]int{"directory.alert_created": 1, "directory.alert_updated": 2, "directory.alert_deleted": 1} {
		if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE tenant_id=$1 AND action=$2`, tenantID, action); n != want {
			test.Errorf("%d %s records, want %d", n, action, want)
		}
	}
}
