//go:build integration

package directory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestPreviewOfSavedMappingsReportsIssueCodes checks, against the database,
// that a refused save answers its mapping code, and that the preview endpoint
// gives every issue with saved mappings its code, target field and message.
func TestPreviewOfSavedMappingsReportsIssueCodes(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID := dbtest.Organization(test)
	actor := dbtest.User(test, organizationID, organizationID)
	service := NewService(&scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{})
	service.SetEventStore(pool)
	router := dbtest.Serve(dbtest.Principal(actor.ID, organizationID), (&Handler{Service: service}).Mount)
	connectionID := "scim:" + organizationID.String()
	base := "/organizations/" + organizationID.String() + "/directory/connections/" + connectionID + "/mappings"

	var saved []Mapping
	for _, rule := range []Mapping{
		{Source: "mail", Target: "email", ValueType: "string", Transform: "lowercase", Enabled: true, Required: true},
		{Source: "department", Target: "department", ValueType: "string", Transform: "trim", Enabled: true, Required: true},
		{Source: "memberOf", Target: "groups", ValueType: "array", Transform: "extract", Pattern: `^CN=([^,]+)`, Enabled: true},
	} {
		response := dbtest.Do(test, router, http.MethodPost, base, rule)
		if response.Code != http.StatusCreated {
			test.Fatalf("create mapping %s: %d %s", rule.Target, response.Code, response.Body.String())
		}
		dbtest.Decode(test, response, &rule)
		saved = append(saved, rule)
	}
	// A refused save answers the mapping code and the field at fault, and writes nothing.
	refused := saved[1]
	refused.Source = "userPassword"
	for _, save := range []struct{ method, path string }{
		{http.MethodPost, base},
		{http.MethodPut, base + "/" + refused.ID.String()},
	} {
		response := dbtest.Do(test, router, save.method, save.path, refused)
		var body struct {
			Error struct {
				Code   string            `json:"code"`
				Fields []errs.FieldError `json:"fields"`
			} `json:"error"`
		}
		dbtest.Decode(test, response, &body)
		if response.Code != http.StatusUnprocessableEntity || body.Error.Code != errs.CodeValidation || len(body.Error.Fields) != 1 ||
			body.Error.Fields[0].Field != "source_attribute" || body.Error.Fields[0].Code != CodeMappingSourceCredential {
			test.Errorf("%s refused mapping: %d %s, want 422 source_attribute %s", save.method, response.Code, response.Body.String(), CodeMappingSourceCredential)
		}
	}
	if count := dbtest.Count(test, `SELECT count(*) FROM organization.directory_mappings WHERE organization_id=$1 AND connection_id=$2 AND (source_attribute='userPassword' OR version<>1)`, organizationID, connectionID); count != 0 {
		test.Fatalf("a refused save changed %d mappings", count)
	}
	// A saved rule that no longer passes validation is reported, not applied.
	if _, err := pool.Exec(ctx, `INSERT INTO organization.directory_mappings(id,organization_id,connection_id,source_attribute,target_field,value_type,transform) VALUES($1,$2,$3,'title','title','array','none')`, uuid.New(), organizationID, connectionID); err != nil {
		test.Fatal(err)
	}

	response := dbtest.Do(test, router, http.MethodPost, base+"/preview", map[string]any{"source": map[string]any{
		"mail": "not-an-email", "department": "   ", "memberOf": []any{"OU=Groups"}, "title": "Engineer",
	}})
	if response.Code != http.StatusOK {
		test.Fatalf("preview: %d %s", response.Code, response.Body.String())
	}
	var preview struct {
		Valid  bool             `json:"valid"`
		Issues []map[string]any `json:"issues"`
	}
	dbtest.Decode(test, response, &preview)
	want := map[string]string{
		"email":      CodeMappingEmailInvalid,
		"department": CodeMappingSourceEmpty,
		"groups":     CodeMappingValueUnmatched,
		"title":      CodeMappingValueTypeMismatch,
	}
	if preview.Valid || len(preview.Issues) != len(want) {
		test.Fatalf("preview = %s, want %d issues", response.Body.String(), len(want))
	}
	for _, issue := range preview.Issues {
		field, _ := issue["field"].(string)
		if issue["code"] != want[field] {
			test.Errorf("issue for %q has code %v, want %q", field, issue["code"], want[field])
		}
		if message, _ := issue["message"].(string); message == "" {
			test.Errorf("issue for %q lost its message", field)
		}
		if id, _ := issue["mapping_id"].(string); uuid.Validate(id) != nil {
			test.Errorf("issue for %q has mapping_id %v", field, issue["mapping_id"])
		}
		delete(want, field)
	}
	if len(want) != 0 {
		test.Errorf("no issue reported for %v", want)
	}
}

func TestSavedMappingAppliesToSCIMAndRejectsStaleOrForeignWrites(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, actorID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organization.organizations(id,slug,name) VALUES($1,$2,'Mapping test')`, organizationID, organizationID.String()); err != nil {
		test.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO account.users(id,organization_id,email,status) VALUES($1,$2,$3,'active')`, actorID, organizationID, actorID.String()+"@example.test"); err != nil {
		test.Fatal(err)
	}
	scimService := scim.NewService(pool, user.NewRepository(pool))
	service := NewService(scimService, &ldapFixture{})
	service.SetEventStore(pool)
	scimService.SetProfileMapper(service)
	_, token, err := scimService.Rotate(ctx, organizationID, audit.Actor{Type: "system"})
	if err != nil {
		test.Fatal(err)
	}
	router := chi.NewRouter()
	(&Handler{Service: service}).Mount(router)
	connectionID := "scim:" + organizationID.String()
	base := "/organizations/" + organizationID.String() + "/directory/connections/" + connectionID + "/mappings"
	call := func(method, path string, body any, principalOrganization uuid.UUID) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(httpx.WithPrincipal(ctx, &httpx.Principal{ActorType: "user", UserID: &actorID, OrganizationID: &principalOrganization}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	rule := Mapping{Source: "department", Target: "department", ValueType: "string", Transform: "uppercase", Enabled: true}
	created := call(http.MethodPost, base, rule, organizationID)
	if created.Code != http.StatusCreated {
		test.Fatalf("create mapping: %d %s", created.Code, created.Body.String())
	}
	if err := json.Unmarshal(created.Body.Bytes(), &rule); err != nil {
		test.Fatal(err)
	}
	// A second enabled mapping to the same field is refused, and nothing of it kept.
	if response := call(http.MethodPost, base, Mapping{Source: "ou", Target: "department", ValueType: "string", Transform: "none", Enabled: true}, organizationID); response.Code != http.StatusConflict {
		test.Fatalf("a second mapping to department: %d %s, want 409", response.Code, response.Body.String())
	}
	if n := dbtest.Count(test, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'directory.mapping_created'`, organizationID); n != 1 {
		test.Fatalf("%d directory.mapping_created rows, want the first mapping's", n)
	}
	preview := call(http.MethodPost, base+"/preview", map[string]any{"source": map[string]any{"department": "engineering"}}, organizationID)
	var mapped MappingPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &mapped); err != nil || !mapped.Valid || mapped.Profile["department"] != "ENGINEERING" {
		test.Fatalf("preview mismatch: %s %v", preview.Body.String(), err)
	}
	if response := call(http.MethodPut, base+"/"+rule.ID.String(), rule, uuid.New()); response.Code != http.StatusForbidden {
		test.Fatalf("foreign write accepted: %d", response.Code)
	}
	updated := call(http.MethodPut, base+"/"+rule.ID.String(), rule, organizationID)
	if updated.Code != http.StatusOK {
		test.Fatalf("update mapping: %s", updated.Body.String())
	}
	if response := call(http.MethodPut, base+"/"+rule.ID.String(), rule, organizationID); response.Code != http.StatusConflict {
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
	if err := pool.QueryRow(ctx, `SELECT profile->>'department' FROM organization.directory_profiles WHERE organization_id=$1 AND user_id=$2 AND connection_id=$3`, organizationID, resource.ID, connectionID).Scan(&department); err != nil || department != "ENGINEERING" {
		test.Fatalf("preview and persisted profile diverged: %q %v", department, err)
	}
	foreignMappings, err := service.Mappings(ctx, uuid.New(), uuid.New().String())
	if err != nil || len(foreignMappings) != 0 {
		test.Fatalf("foreign mappings visible: %+v %v", foreignMappings, err)
	}
}

// TestPersonsDirectoryProfileIsReturned checks that a person's mapped profile
// comes back per connection, named, and that another organization's person
// has none here.
func TestPersonsDirectoryProfileIsReturned(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	organizationID, other := dbtest.Organization(test), dbtest.Organization(test)
	admin, person, elsewhere := dbtest.User(test, organizationID, organizationID), dbtest.User(test, organizationID, organizationID), dbtest.User(test, other, other)
	connection := uuid.New()
	service := NewService(&scimFixture{config: &scim.ConfigView{}}, &ldapFixture{records: []ldap.Connection{{ID: connection, OrganizationID: organizationID, Name: "Head office"}}})
	service.SetEventStore(pool)
	for _, row := range []struct {
		organization, user uuid.UUID
	}{{organizationID, person.ID}, {other, elsewhere.ID}} {
		if _, err := pool.Exec(ctx, `INSERT INTO organization.directory_profiles (organization_id, user_id, connection_id, profile) VALUES ($1, $2, $3, '{"title": "Engineer", "groups": ["eng"]}')`,
			row.organization, row.user, connection.String()); err != nil {
			test.Fatal(err)
		}
	}
	h := dbtest.Serve(dbtest.Principal(admin.ID, organizationID), (&Handler{Service: service}).Mount)
	var got struct {
		Items []Profile `json:"items"`
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, "/organizations/"+organizationID.String()+"/directory/profiles/"+person.ID.String(), nil), &got)
	if len(got.Items) != 1 || got.Items[0].ConnectionName != "Head office" || got.Items[0].Fields["title"] != "Engineer" {
		test.Errorf("profile %+v; want one from Head office with the title", got.Items)
	}
	dbtest.Decode(test, dbtest.Do(test, h, http.MethodGet, "/organizations/"+organizationID.String()+"/directory/profiles/"+elsewhere.ID.String(), nil), &got)
	if len(got.Items) != 0 {
		test.Errorf("another organization's person: %+v, want nothing", got.Items)
	}
}
