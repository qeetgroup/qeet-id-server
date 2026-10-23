//go:build integration

package directory

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestPreviewOfSavedMappingsReportsIssueCodes checks, against the database,
// that a refused save answers its mapping code, and that the preview endpoint
// gives every issue with saved mappings its code, target field and message.
func TestPreviewOfSavedMappingsReportsIssueCodes(test *testing.T) {
	pool := dbtest.Pool(test)
	ctx := dbtest.Context(test)
	tenantID := dbtest.Tenant(test)
	actor := dbtest.User(test, tenantID, tenantID)
	service := NewService(&scimFixture{config: &scim.ConfigView{TokenSet: true}}, &ldapFixture{})
	service.SetEventStore(pool)
	router := dbtest.Serve(dbtest.Principal(actor.ID, tenantID), (&Handler{Service: service}).Mount)
	connectionID := "scim:" + tenantID.String()
	base := "/tenants/" + tenantID.String() + "/directory/connections/" + connectionID + "/mappings"

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
	if count := dbtest.Count(test, `SELECT count(*) FROM tenant.directory_mappings WHERE tenant_id=$1 AND connection_id=$2 AND (source_attribute='userPassword' OR version<>1)`, tenantID, connectionID); count != 0 {
		test.Fatalf("a refused save changed %d mappings", count)
	}
	// A saved rule that no longer passes validation is reported, not applied.
	if _, err := pool.Exec(ctx, `INSERT INTO tenant.directory_mappings(id,tenant_id,connection_id,source_attribute,target_field,value_type,transform) VALUES($1,$2,$3,'title','title','array','none')`, uuid.New(), tenantID, connectionID); err != nil {
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
