//go:build integration

package directory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

func TestSuspendedDirectoryPrivacyReviewAndReactivation(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, foreignOrganization, actorID, ownedID, foreignID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, organization := range []uuid.UUID{organizationID, foreignOrganization} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Suspension test')`, organization, organization.String()); err != nil {
			test.Fatal(err)
		}
	}
	for _, record := range []struct {
		id, organization uuid.UUID
		status           string
	}{{actorID, organizationID, "active"}, {ownedID, organizationID, "suspended"}, {foreignID, foreignOrganization, "suspended"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO account.users(id,organization_id,email,status) VALUES($1,$2,$3,$4)`, record.id, record.organization, record.id.String()+"@example.test", record.status); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET suspension_risk='high',suspension_reason='account_compromise' WHERE id=$1`, foreignID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.roles(id,organization_id,name) VALUES($1,$2,'directory-reader')`, roleID, organizationID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO rbac.user_roles(user_id,organization_id,role_id) VALUES($1,$2,$3)`, foreignID, organizationID, roleID); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth.sessions(user_id,organization_id) VALUES($1,$2)`, ownedID, organizationID); err != nil {
		test.Fatal(err)
	}
	repository := user.NewRepository(pool)
	page, err := repository.ListSuspended(ctx, organizationID, user.SuspensionFilters{Limit: 25})
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
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &actorID, OrganizationID: &organizationID}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	selfRequest := httptest.NewRequest(http.MethodPost, "/users/"+ownedID.String()+"/reactivate", nil)
	selfRequest = selfRequest.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &ownedID, OrganizationID: &organizationID}))
	selfResponse := httptest.NewRecorder()
	router.ServeHTTP(selfResponse, selfRequest)
	if selfResponse.Code != http.StatusForbidden {
		test.Fatalf("self reactivation accepted: %d", selfResponse.Code)
	}
	// foreignID's home is another organization, so this one may not manage the account.
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
	page, err = repository.ListSuspended(ctx, organizationID, user.SuspensionFilters{Limit: 25})
	if err != nil || page.Total != 1 || page.Items[0].ID != foreignID {
		test.Fatalf("reactivated user remained listed: %+v %v", page, err)
	}
}

// TestConnectionsCountTheirPeopleAndGroups checks that each LDAP connection
// counts the people it signed in, not deleted ones or another connection's,
// and that SCIM counts the groups it provisioned, in this organization only.
func TestConnectionsCountTheirPeopleAndGroups(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, other := dbtest.Organization(test), dbtest.Organization(test)
	first, second := uuid.New(), uuid.New()
	service := NewService(&scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{records: []ldap.Connection{
		{ID: first, OrganizationID: organizationID, Name: "Head office"}, {ID: second, OrganizationID: organizationID, Name: "Branch"},
	}})
	service.SetEventStore(pool)
	link := func(organization uuid.UUID, connection uuid.UUID) uuid.UUID {
		person := dbtest.User(test, organization, organization)
		if _, err := pool.Exec(ctx, `INSERT INTO account.external_identities (user_id, organization_id, provider, subject, connection_id) VALUES ($1, $2, 'ldap', $3, $4)`,
			person.ID, organization, uuid.NewString(), connection); err != nil {
			test.Fatal(err)
		}
		return person.ID
	}
	link(organizationID, first)
	link(organizationID, first)
	gone := link(organizationID, first)
	if _, err := pool.Exec(ctx, `UPDATE account.users SET deleted_at = NOW() WHERE id = $1`, gone); err != nil {
		test.Fatal(err)
	}
	link(other, first) // another organization's identity naming the same id
	for _, organization := range []uuid.UUID{organizationID, organizationID, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.groups (organization_id, name, provisioned_via) VALUES ($1, $2, 'scim')`, organization, uuid.NewString()); err != nil {
			test.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO organization.groups (organization_id, name) VALUES ($1, 'Made by an admin')`, organizationID); err != nil {
		test.Fatal(err)
	}

	connections, err := service.List(ctx, organizationID)
	if err != nil {
		test.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range connections {
		users, groups := "nil", "nil"
		if c.UserCount != nil {
			users = strconv.Itoa(*c.UserCount)
		}
		if c.GroupCount != nil {
			groups = strconv.Itoa(*c.GroupCount)
		}
		got[c.Type+":"+c.Name] = users + "/" + groups
	}
	if got["ldap:Head office"] != "2/nil" || got["ldap:Branch"] != "0/nil" || got["scim:SCIM"] != "0/2" {
		test.Errorf("counts %v; want Head office 2 people, Branch 0, SCIM 2 groups", got)
	}
}
