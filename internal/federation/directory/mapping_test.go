package directory

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/federation/ldap"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func TestMappingTransformsShareValidationAndPreview(test *testing.T) {
	email := Mapping{ID: uuid.New(), Source: "mail", Target: "email", ValueType: "string", Transform: "lowercase", Enabled: true, Required: true}
	groups := Mapping{ID: uuid.New(), Source: "memberOf", Target: "groups", ValueType: "array", Transform: "extract", Pattern: `(?i)^CN=([^,]+)`, Enabled: true}
	name := Mapping{ID: uuid.New(), Source: "/name/givenName", Target: "first_name", ValueType: "string", Transform: "trim", Enabled: true}
	result := PreviewMappings([]Mapping{email, groups, name}, map[string]any{"mail": " ALEX@EXAMPLE.TEST ", "memberOf": []any{"CN=Engineering,OU=Groups", "CN=Product,OU=Groups"}, "name": map[string]any{"givenName": " Alex "}}, false)
	if !result.Valid || result.Profile["email"] != "alex@example.test" || result.Profile["first_name"] != "Alex" {
		test.Fatalf("unexpected preview: %+v", result)
	}
	values, ok := result.Profile["groups"].([]string)
	if !ok || len(values) != 2 || values[0] != "Engineering" {
		test.Fatalf("invalid array transformation: %+v", result.Profile)
	}
}

func TestMappingsCannotGrantPrivilegesOrReadSecrets(test *testing.T) {
	mapping := Mapping{ID: uuid.New(), Source: "department", Target: "department", ValueType: "string", Transform: "none", Enabled: true}
	for _, target := range []string{"roles", "permissions", "tenant_id", "status", "password", "metadata", "is_admin"} {
		candidate := mapping
		candidate.Target = target
		if ValidateMapping(candidate) == nil {
			test.Fatalf("accepted unsafe target %s", target)
		}
	}
	for _, source := range []string{"password", "/credentials/secret", "access_token", "PrivateKey"} {
		candidate := mapping
		candidate.Source = source
		if ValidateMapping(candidate) == nil {
			test.Fatalf("accepted credential source %s", source)
		}
	}
}

func TestMappingLimitsFailuresAndPartialUpdates(test *testing.T) {
	mapping := Mapping{ID: uuid.New(), Source: "mail", Target: "email", ValueType: "string", Transform: "none", Enabled: true, Required: true}
	if PreviewMappings([]Mapping{mapping}, map[string]any{}, false).Valid {
		test.Fatal("missing required field passed")
	}
	if !PreviewMappings([]Mapping{mapping}, map[string]any{}, true).Valid {
		test.Fatal("partial update enforced untouched required field")
	}
	if PreviewMappings([]Mapping{mapping}, map[string]any{"mail": "invalid"}, false).Valid {
		test.Fatal("invalid email passed")
	}
	if PreviewMappings([]Mapping{mapping, mapping}, map[string]any{"mail": "alex@example.test"}, false).Valid {
		test.Fatal("duplicate target passed")
	}
	mapping.Transform = "extract"
	mapping.Pattern = "("
	if ValidateMapping(mapping) == nil {
		test.Fatal("invalid regexp passed")
	}
	mapping.Pattern = "(a)(b)"
	if ValidateMapping(mapping) == nil {
		test.Fatal("multiple captures passed")
	}
	mapping.Pattern = strings.Repeat("a", 257)
	if ValidateMapping(mapping) == nil {
		test.Fatal("unbounded pattern passed")
	}
	result := PreviewMappings(nil, map[string]any{"value": strings.Repeat("x", 65537)}, false)
	if result.Valid {
		test.Fatal("oversized source passed")
	}
}

func TestLDAPValuesAndMappedAttributeRemoval(test *testing.T) {
	mapping := Mapping{ID: uuid.New(), Source: "department", Target: "department", ValueType: "string", Transform: "trim", Enabled: true}
	result := PreviewMappings([]Mapping{mapping}, map[string]any{"department": []string{" Engineering "}}, false)
	if !result.Valid || result.Profile["department"] != "Engineering" {
		test.Fatalf("LDAP value was not mapped: %+v", result)
	}
	result = PreviewMappings([]Mapping{mapping}, map[string]any{"department": nil}, true)
	if value, exists := result.Profile["department"]; !result.Valid || !exists || value != nil {
		test.Fatalf("partial removal was lost: %+v", result)
	}
}

// TestPreviewIssuesCarryTheirCode checks that each kind of issue reports its
// own code from mappingIssueCodes, names the mapping's target field and keeps
// its message, and that every listed code is one some issue reports.
func TestPreviewIssuesCarryTheirCode(test *testing.T) {
	text := func(target string) Mapping {
		return Mapping{ID: uuid.New(), Source: "attribute", Target: target, ValueType: "string", Transform: "none", Enabled: true}
	}
	groups := Mapping{ID: uuid.New(), Source: "memberOf", Target: "groups", ValueType: "array", Transform: "extract", Pattern: `^CN=([^,]+)`, Enabled: true}
	with := func(mapping Mapping, change func(*Mapping)) Mapping {
		change(&mapping)
		return mapping
	}
	cases := []struct {
		name     string
		mappings []Mapping
		source   map[string]any
		code     string
	}{
		{"oversized source", nil, map[string]any{"value": strings.Repeat("x", 65537)}, CodeMappingPreviewTooLarge},
		{"too many mappings", make([]Mapping, 51), map[string]any{}, CodeMappingPreviewTooLarge},
		{"empty source attribute", []Mapping{with(text("title"), func(m *Mapping) { m.Source = "" })}, map[string]any{}, CodeMappingSourceInvalid},
		{"padded source attribute", []Mapping{with(text("title"), func(m *Mapping) { m.Source = " title" })}, map[string]any{}, CodeMappingSourceInvalid},
		{"credential source", []Mapping{with(text("title"), func(m *Mapping) { m.Source = "userPassword" })}, map[string]any{}, CodeMappingSourceCredential},
		{"unsupported target", []Mapping{text("roles")}, map[string]any{}, CodeMappingTargetUnsupported},
		{"duplicate target", []Mapping{text("title"), text("title")}, map[string]any{"attribute": "Engineer"}, CodeMappingTargetDuplicate},
		{"value type mismatch", []Mapping{text("groups")}, map[string]any{}, CodeMappingValueTypeMismatch},
		{"unsupported transform", []Mapping{with(text("title"), func(m *Mapping) { m.Transform = "reverse" })}, map[string]any{}, CodeMappingTransformUnsupported},
		{"pattern without extract", []Mapping{with(text("title"), func(m *Mapping) { m.Transform, m.Pattern = "trim", "(x)" })}, map[string]any{}, CodeMappingPatternUnexpected},
		{"empty extract pattern", []Mapping{with(groups, func(m *Mapping) { m.Pattern = "" })}, map[string]any{}, CodeMappingPatternInvalid},
		{"unparsable extract pattern", []Mapping{with(groups, func(m *Mapping) { m.Pattern = "(" })}, map[string]any{}, CodeMappingPatternInvalid},
		{"two capture groups", []Mapping{with(groups, func(m *Mapping) { m.Pattern = "(a)(b)" })}, map[string]any{}, CodeMappingPatternInvalid},
		{"required attribute missing", []Mapping{with(text("title"), func(m *Mapping) { m.Required = true })}, map[string]any{}, CodeMappingSourceMissing},
		{"required attribute empty", []Mapping{with(text("title"), func(m *Mapping) { m.Required, m.Transform = true, "trim" })}, map[string]any{"attribute": "   "}, CodeMappingSourceEmpty},
		{"value not a string", []Mapping{text("title")}, map[string]any{"attribute": 42.0}, CodeMappingValueNotString},
		{"value not an array", []Mapping{groups}, map[string]any{"memberOf": "CN=Engineering"}, CodeMappingValueNotArray},
		{"array entry not a string", []Mapping{groups}, map[string]any{"memberOf": []any{"CN=Engineering", 7.0}}, CodeMappingValueNotArray},
		{"value too long", []Mapping{text("title")}, map[string]any{"attribute": strings.Repeat("x", 2049)}, CodeMappingValueTooLong},
		{"too many array entries", []Mapping{groups}, map[string]any{"memberOf": make([]any, 101)}, CodeMappingValueTooMany},
		{"value does not match the pattern", []Mapping{groups}, map[string]any{"memberOf": []any{"OU=Groups"}}, CodeMappingValueUnmatched},
		{"invalid email", []Mapping{text("email")}, map[string]any{"attribute": "not-an-email"}, CodeMappingEmailInvalid},
		{"display name too long", []Mapping{text("display_name")}, map[string]any{"attribute": strings.Repeat("x", 201)}, CodeMappingDisplayNameTooLong},
	}
	reported := map[string]bool{}
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			result := PreviewMappings(scenario.mappings, scenario.source, false)
			if result.Valid || len(result.Issues) != 1 {
				test.Fatalf("want one issue, got valid=%v issues=%+v", result.Valid, result.Issues)
			}
			issue := result.Issues[0]
			reported[issue.Code] = true
			if issue.Code != scenario.code || !slices.Contains(mappingIssueCodes, issue.Code) {
				test.Errorf("code = %q, want listed code %q", issue.Code, scenario.code)
			}
			if issue.Message == "" {
				test.Error("issue lost its message")
			}
			wantField := ""
			if scenario.code != CodeMappingPreviewTooLarge {
				wantField = scenario.mappings[len(scenario.mappings)-1].Target
			}
			if issue.Field != wantField {
				test.Errorf("field = %q, want %q", issue.Field, wantField)
			}
			raw, err := json.Marshal(issue)
			if err != nil {
				test.Fatal(err)
			}
			var keys map[string]any
			if err := json.Unmarshal(raw, &keys); err != nil {
				test.Fatal(err)
			}
			for _, key := range []string{"mapping_id", "field", "code", "message"} {
				if _, ok := keys[key]; !ok {
					test.Errorf("issue JSON %s has no %q", raw, key)
				}
			}
		})
	}
	for _, code := range mappingIssueCodes {
		if !reported[code] {
			test.Errorf("no case reports listed code %q", code)
		}
	}
}

// TestSaveRefusesAnInvalidMappingWithItsCode checks that saving a mapping the
// rules refuse answers 422 validation_failed naming the field at fault and the
// mapping code, before anything is written.
func TestSaveRefusesAnInvalidMappingWithItsCode(test *testing.T) {
	tenantID := uuid.New()
	ldapID := uuid.New()
	valid := Mapping{Source: "department", Target: "department", ValueType: "string", Transform: "none", Enabled: true}
	with := func(change func(*Mapping)) Mapping {
		mapping := valid
		change(&mapping)
		return mapping
	}
	scimPath := "/tenants/" + tenantID.String() + "/directory/connections/scim:" + tenantID.String() + "/mappings"
	ldapPath := "/tenants/" + tenantID.String() + "/directory/connections/" + ldapID.String() + "/mappings"
	cases := []struct {
		name, method, path string
		mapping            Mapping
		field, code        string
	}{
		{"credential source", http.MethodPost, scimPath, with(func(m *Mapping) { m.Source = "userPassword" }), "source_attribute", CodeMappingSourceCredential},
		{"padded source", http.MethodPut, scimPath + "/" + uuid.NewString(), with(func(m *Mapping) { m.Source, m.Version = " department", 1 }), "source_attribute", CodeMappingSourceInvalid},
		{"unsupported target", http.MethodPost, scimPath, with(func(m *Mapping) { m.Target = "roles" }), "target_field", CodeMappingTargetUnsupported},
		{"value type mismatch", http.MethodPost, scimPath, with(func(m *Mapping) { m.ValueType = "array" }), "value_type", CodeMappingValueTypeMismatch},
		{"unsupported transform", http.MethodPost, scimPath, with(func(m *Mapping) { m.Transform = "reverse" }), "transform", CodeMappingTransformUnsupported},
		{"pattern without extract", http.MethodPost, scimPath, with(func(m *Mapping) { m.Pattern = "(x)" }), "pattern", CodeMappingPatternUnexpected},
		{"invalid extract pattern", http.MethodPost, scimPath, with(func(m *Mapping) { m.Transform, m.Pattern = "extract", "(" }), "pattern", CodeMappingPatternInvalid},
		{"LDAP source not an attribute name", http.MethodPost, ldapPath, with(func(m *Mapping) { m.Source = "/name/givenName" }), "source_attribute", CodeMappingSourceInvalid},
	}
	for _, scenario := range cases {
		test.Run(scenario.name, func(test *testing.T) {
			ldapSource := &ldapFixture{records: []ldap.Connection{{ID: ldapID, TenantID: tenantID, Name: "Corporate", Status: "active"}}}
			router := chi.NewRouter()
			(&Handler{Service: NewService(&scimFixture{config: &scim.ConfigView{TokenSet: true}}, ldapSource)}).Mount(router)
			raw, err := json.Marshal(scenario.mapping)
			if err != nil {
				test.Fatal(err)
			}
			request := httptest.NewRequest(scenario.method, scenario.path, bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(httpx.WithPrincipal(request.Context(), &httpx.Principal{ActorType: "user", TenantID: &tenantID}))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			var body struct {
				Error struct {
					Code   string            `json:"code"`
					Fields []errs.FieldError `json:"fields"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				test.Fatal(err)
			}
			if response.Code != http.StatusUnprocessableEntity || body.Error.Code != errs.CodeValidation || len(body.Error.Fields) != 1 {
				test.Fatalf("got %d %s, want 422 validation_failed with one field", response.Code, response.Body.String())
			}
			got := body.Error.Fields[0]
			if got.Field != scenario.field || got.Code != scenario.code || got.Message == "" {
				test.Errorf("field error = %+v, want field %q code %q", got, scenario.field, scenario.code)
			}
		})
	}
}
