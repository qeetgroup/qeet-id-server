package directory

import (
	"strings"
	"testing"

	"github.com/google/uuid"
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
