package abac

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// subjectBag returns a bag with only a "subject" namespace.
func subjectBag(attrs map[string]any) AttributeBag {
	return AttributeBag{"subject": attrs}
}

// resourceBag returns a bag with only a "resource" namespace.
func resourceBag(attrs map[string]any) AttributeBag {
	return AttributeBag{"resource": attrs}
}

// contextBag returns a bag with only a "context" namespace.
func contextBag(attrs map[string]any) AttributeBag {
	return AttributeBag{"context": attrs}
}

// eval evaluates a condition that compares no two attributes, failing t if the
// answer depends on whether the policy allows or denies.
func eval(t *testing.T, condJSON string, b AttributeBag) bool {
	t.Helper()
	ok, err := EvaluateCondition(json.RawMessage(condJSON), "allow", b)
	if err != nil {
		t.Fatalf("EvaluateCondition error: %v", err)
	}
	if deny, _ := EvaluateCondition(json.RawMessage(condJSON), "deny", b); deny != ok {
		t.Fatalf("%s: holds %v for an allow but %v for a deny", condJSON, ok, deny)
	}
	return ok
}

// Empty / no-op conditions.

func TestEvaluateCondition_EmptyIsTrue(t *testing.T) {
	if !eval(t, `{}`, AttributeBag{}) {
		t.Error("empty condition must always be true")
	}
	if !eval(t, `null`, AttributeBag{}) {
		t.Error("null condition must always be true")
	}
}

// eq / ne

func TestEvaluateCondition_Eq(t *testing.T) {
	b := subjectBag(map[string]any{"department": "eng"})
	if !eval(t, `{"attr":"subject.department","op":"eq","value":"eng"}`, b) {
		t.Error("eq: matching string should be true")
	}
	if eval(t, `{"attr":"subject.department","op":"eq","value":"ops"}`, b) {
		t.Error("eq: non-matching string should be false")
	}
}

func TestEvaluateCondition_Eq_Number(t *testing.T) {
	b := contextBag(map[string]any{"level": float64(5)})
	if !eval(t, `{"attr":"context.level","op":"eq","value":5}`, b) {
		t.Error("eq: matching number should be true")
	}
	if eval(t, `{"attr":"context.level","op":"eq","value":6}`, b) {
		t.Error("eq: non-matching number should be false")
	}
}

func TestEvaluateCondition_Eq_Bool(t *testing.T) {
	b := subjectBag(map[string]any{"admin": true})
	if !eval(t, `{"attr":"subject.admin","op":"eq","value":true}`, b) {
		t.Error("eq: bool true should match")
	}
	if eval(t, `{"attr":"subject.admin","op":"eq","value":false}`, b) {
		t.Error("eq: bool false should not match true")
	}
}

func TestEvaluateCondition_Ne(t *testing.T) {
	b := subjectBag(map[string]any{"role": "viewer"})
	if !eval(t, `{"attr":"subject.role","op":"ne","value":"admin"}`, b) {
		t.Error("ne: different values should be true")
	}
	if eval(t, `{"attr":"subject.role","op":"ne","value":"viewer"}`, b) {
		t.Error("ne: same value should be false")
	}
}

// in / nin

func TestEvaluateCondition_In(t *testing.T) {
	b := subjectBag(map[string]any{"role": "editor"})
	if !eval(t, `{"attr":"subject.role","op":"in","value":["admin","editor","owner"]}`, b) {
		t.Error("in: value in array should be true")
	}
	if eval(t, `{"attr":"subject.role","op":"in","value":["viewer","guest"]}`, b) {
		t.Error("in: value not in array should be false")
	}
}

func TestEvaluateCondition_Nin(t *testing.T) {
	b := subjectBag(map[string]any{"role": "guest"})
	if !eval(t, `{"attr":"subject.role","op":"nin","value":["admin","editor"]}`, b) {
		t.Error("nin: value not in array should be true")
	}
	if eval(t, `{"attr":"subject.role","op":"nin","value":["guest","viewer"]}`, b) {
		t.Error("nin: value in array should be false")
	}
}

// contains

func TestEvaluateCondition_Contains_String(t *testing.T) {
	b := resourceBag(map[string]any{"path": "/api/v1/users"})
	if !eval(t, `{"attr":"resource.path","op":"contains","value":"/v1/"}`, b) {
		t.Error("contains: substring should match")
	}
	if eval(t, `{"attr":"resource.path","op":"contains","value":"/v2/"}`, b) {
		t.Error("contains: absent substring should be false")
	}
}

func TestEvaluateCondition_Contains_Array(t *testing.T) {
	b := subjectBag(map[string]any{"tags": []any{"read", "write", "delete"}})
	if !eval(t, `{"attr":"subject.tags","op":"contains","value":"write"}`, b) {
		t.Error("contains: element in array should be true")
	}
	if eval(t, `{"attr":"subject.tags","op":"contains","value":"admin"}`, b) {
		t.Error("contains: element not in array should be false")
	}
}

// Numeric comparisons: gt, gte, lt, lte

func TestEvaluateCondition_Gt(t *testing.T) {
	b := contextBag(map[string]any{"hour": float64(14)})
	if !eval(t, `{"attr":"context.hour","op":"gt","value":9}`, b) {
		t.Error("gt: 14 > 9 should be true")
	}
	if eval(t, `{"attr":"context.hour","op":"gt","value":14}`, b) {
		t.Error("gt: 14 > 14 should be false")
	}
	if eval(t, `{"attr":"context.hour","op":"gt","value":20}`, b) {
		t.Error("gt: 14 > 20 should be false")
	}
}

func TestEvaluateCondition_Gte(t *testing.T) {
	b := contextBag(map[string]any{"hour": float64(9)})
	if !eval(t, `{"attr":"context.hour","op":"gte","value":9}`, b) {
		t.Error("gte: 9 >= 9 should be true")
	}
	if eval(t, `{"attr":"context.hour","op":"gte","value":10}`, b) {
		t.Error("gte: 9 >= 10 should be false")
	}
}

func TestEvaluateCondition_Lt(t *testing.T) {
	b := contextBag(map[string]any{"score": float64(0.3)})
	if !eval(t, `{"attr":"context.score","op":"lt","value":0.5}`, b) {
		t.Error("lt: 0.3 < 0.5 should be true")
	}
	if eval(t, `{"attr":"context.score","op":"lt","value":0.3}`, b) {
		t.Error("lt: 0.3 < 0.3 should be false")
	}
}

func TestEvaluateCondition_Lte(t *testing.T) {
	b := contextBag(map[string]any{"score": float64(0.5)})
	if !eval(t, `{"attr":"context.score","op":"lte","value":0.5}`, b) {
		t.Error("lte: 0.5 <= 0.5 should be true")
	}
	if eval(t, `{"attr":"context.score","op":"lte","value":0.4}`, b) {
		t.Error("lte: 0.5 <= 0.4 should be false")
	}
}

// exists

func TestEvaluateCondition_Exists(t *testing.T) {
	b := subjectBag(map[string]any{"email": "alice@example.com"})
	if !eval(t, `{"attr":"subject.email","op":"exists"}`, b) {
		t.Error("exists: present attr should be true")
	}
	if eval(t, `{"attr":"subject.phone","op":"exists"}`, b) {
		t.Error("exists: absent attr should be false")
	}
}

// prefix / suffix

func TestEvaluateCondition_Prefix(t *testing.T) {
	b := resourceBag(map[string]any{"name": "prod-api-gateway"})
	if !eval(t, `{"attr":"resource.name","op":"prefix","value":"prod-"}`, b) {
		t.Error("prefix: matching prefix should be true")
	}
	if eval(t, `{"attr":"resource.name","op":"prefix","value":"staging-"}`, b) {
		t.Error("prefix: non-matching prefix should be false")
	}
}

func TestEvaluateCondition_Suffix(t *testing.T) {
	b := resourceBag(map[string]any{"filename": "report.pdf"})
	if !eval(t, `{"attr":"resource.filename","op":"suffix","value":".pdf"}`, b) {
		t.Error("suffix: matching suffix should be true")
	}
	if eval(t, `{"attr":"resource.filename","op":"suffix","value":".txt"}`, b) {
		t.Error("suffix: non-matching suffix should be false")
	}
}

// regex

func TestEvaluateCondition_Regex_Match(t *testing.T) {
	b := subjectBag(map[string]any{"email": "alice@qeet.in"})
	if !eval(t, `{"attr":"subject.email","op":"regex","value":"^[a-z]+@qeet\\.in$"}`, b) {
		t.Error("regex: matching pattern should be true")
	}
	if eval(t, `{"attr":"subject.email","op":"regex","value":"^[a-z]+@acme\\.com$"}`, b) {
		t.Error("regex: non-matching pattern should be false")
	}
}

func TestEvaluateCondition_Regex_BadPattern_FailClosed(t *testing.T) {
	b := subjectBag(map[string]any{"email": "alice@example.com"})
	// A bad regex should fail-closed (return false, not error — so the condition
	// evaluator itself does not return an error for bad patterns).
	ok, err := EvaluateCondition(json.RawMessage(`{"attr":"subject.email","op":"regex","value":"[invalid"}`), "allow", b)
	if err != nil {
		t.Fatalf("bad regex must not propagate an error: %v", err)
	}
	if ok {
		t.Error("bad regex must fail-closed (return false)")
	}
}

// Logical gates: all, any, not

func TestEvaluateCondition_All(t *testing.T) {
	b := subjectBag(map[string]any{"role": "admin", "active": true})
	allTrue := `{"all":[
		{"attr":"subject.role","op":"eq","value":"admin"},
		{"attr":"subject.active","op":"eq","value":true}
	]}`
	if !eval(t, allTrue, b) {
		t.Error("all: all children true should be true")
	}
	partialFalse := `{"all":[
		{"attr":"subject.role","op":"eq","value":"admin"},
		{"attr":"subject.active","op":"eq","value":false}
	]}`
	if eval(t, partialFalse, b) {
		t.Error("all: one false child should make the whole all false")
	}
}

func TestEvaluateCondition_All_Empty(t *testing.T) {
	// Vacuously true.
	if !eval(t, `{"all":[]}`, AttributeBag{}) {
		t.Error("all with empty array is vacuously true")
	}
}

func TestEvaluateCondition_Any(t *testing.T) {
	b := subjectBag(map[string]any{"role": "viewer"})
	anyTrue := `{"any":[
		{"attr":"subject.role","op":"eq","value":"admin"},
		{"attr":"subject.role","op":"eq","value":"viewer"}
	]}`
	if !eval(t, anyTrue, b) {
		t.Error("any: at least one true should be true")
	}
	anyFalse := `{"any":[
		{"attr":"subject.role","op":"eq","value":"admin"},
		{"attr":"subject.role","op":"eq","value":"editor"}
	]}`
	if eval(t, anyFalse, b) {
		t.Error("any: all false children should be false")
	}
}

func TestEvaluateCondition_Any_Empty(t *testing.T) {
	// OR of nothing is false.
	if eval(t, `{"any":[]}`, AttributeBag{}) {
		t.Error("any with empty array must be false")
	}
}

func TestEvaluateCondition_Not(t *testing.T) {
	b := subjectBag(map[string]any{"role": "guest"})
	if !eval(t, `{"not":{"attr":"subject.role","op":"eq","value":"admin"}}`, b) {
		t.Error("not: inverting a false condition should be true")
	}
	if eval(t, `{"not":{"attr":"subject.role","op":"eq","value":"guest"}}`, b) {
		t.Error("not: inverting a true condition should be false")
	}
}

// Nested conditions

func TestEvaluateCondition_Nested(t *testing.T) {
	// (department == "eng" AND level >= 3) OR role == "admin"
	b := AttributeBag{
		"subject": map[string]any{
			"department": "eng",
			"level":      float64(3),
			"role":       "member",
		},
	}
	cond := `{"any":[
		{"all":[
			{"attr":"subject.department","op":"eq","value":"eng"},
			{"attr":"subject.level","op":"gte","value":3}
		]},
		{"attr":"subject.role","op":"eq","value":"admin"}
	]}`
	if !eval(t, cond, b) {
		t.Error("nested: eng level-3 member should pass the any(all) gate")
	}

	// Change level to 2 and role is still member → should fail.
	b2 := AttributeBag{
		"subject": map[string]any{
			"department": "eng",
			"level":      float64(2),
			"role":       "member",
		},
	}
	if eval(t, cond, b2) {
		t.Error("nested: eng level-2 member should fail the gate")
	}

	// Admin always passes via the second branch.
	b3 := AttributeBag{
		"subject": map[string]any{
			"department": "ops",
			"level":      float64(1),
			"role":       "admin",
		},
	}
	if !eval(t, cond, b3) {
		t.Error("nested: admin role should pass via the second any branch")
	}
}

// Missing / absent attributes

func TestEvaluateCondition_MissingAttr_FailClosed(t *testing.T) {
	empty := AttributeBag{"subject": {}}

	// All comparison ops on a missing attribute return false.
	for _, op := range []string{"eq", "ne", "gt", "gte", "lt", "lte", "contains", "prefix", "suffix", "regex", "in"} {
		val := `"anything"`
		if op == "in" {
			val = `["a","b"]`
		}
		cond := `{"attr":"subject.missing","op":"` + op + `","value":` + val + `}`
		if eval(t, cond, empty) {
			t.Errorf("op %q on absent attr must return false (fail-closed)", op)
		}
	}
}

func TestEvaluateCondition_MissingAttr_Exists(t *testing.T) {
	b := AttributeBag{"subject": {}}
	if eval(t, `{"attr":"subject.missing","op":"exists"}`, b) {
		t.Error("exists on absent attr must be false")
	}
}

func TestEvaluateCondition_MissingAttr_Nin(t *testing.T) {
	b := AttributeBag{"subject": {}}
	// An absent attr is not a member of any set → nin returns true.
	if !eval(t, `{"attr":"subject.missing","op":"nin","value":["a","b"]}`, b) {
		t.Error("nin on absent attr must be true (absent is not-in any set)")
	}
}

func TestEvaluateCondition_MissingNamespace(t *testing.T) {
	// Bag has no "resource" namespace at all.
	b := subjectBag(map[string]any{"role": "admin"})
	if eval(t, `{"attr":"resource.type","op":"eq","value":"doc"}`, b) {
		t.Error("missing namespace must be treated as absent (false)")
	}
}

// Multi-segment nested attribute path

func TestEvaluateCondition_NestedAttrPath(t *testing.T) {
	b := AttributeBag{
		"subject": map[string]any{
			"profile": map[string]any{
				"department": "security",
			},
		},
	}
	if !eval(t, `{"attr":"subject.profile.department","op":"eq","value":"security"}`, b) {
		t.Error("nested attr path must resolve through inner maps")
	}
}

// Malformed JSON → error (fail-closed at caller)

func TestEvaluateCondition_MalformedJSON(t *testing.T) {
	_, err := EvaluateCondition(json.RawMessage(`{invalid json`), "deny", AttributeBag{})
	if err == nil {
		t.Error("malformed JSON must return an error")
	}
}

func TestEvaluateCondition_UnknownOp(t *testing.T) {
	b := subjectBag(map[string]any{"x": "y"})
	_, err := EvaluateCondition(json.RawMessage(`{"attr":"subject.x","op":"superop","value":"y"}`), "deny", b)
	if err == nil {
		t.Error("unknown operator must return an error")
	}
}

func TestEvaluateCondition_UnrecognizedNode(t *testing.T) {
	_, err := EvaluateCondition(json.RawMessage(`{"bogus":"field"}`), "deny", AttributeBag{})
	if err == nil {
		t.Error("node with no recognized key must return an error")
	}
}

// validateCondition

func TestValidateCondition_Empty(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{}`)); err != nil {
		t.Errorf("empty condition must be valid: %v", err)
	}
}

func TestValidateCondition_ValidLeaf(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","op":"eq","value":"eng"}`)); err != nil {
		t.Errorf("valid leaf must pass validation: %v", err)
	}
}

func TestValidateCondition_UnknownOp(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","op":"badop","value":"eng"}`)); err == nil {
		t.Error("unknown op must fail validation")
	}
}

func TestValidateCondition_MissingOp(t *testing.T) {
	if err := validateCondition(json.RawMessage(`{"attr":"subject.dept","value":"eng"}`)); err == nil {
		t.Error("missing op must fail validation")
	}
}

func TestValidateCondition_ValidNested(t *testing.T) {
	cond := `{"all":[{"any":[{"attr":"subject.role","op":"eq","value":"admin"}]},{"not":{"attr":"subject.suspended","op":"eq","value":true}}]}`
	if err := validateCondition(json.RawMessage(cond)); err != nil {
		t.Errorf("valid nested condition must pass validation: %v", err)
	}
}

func TestValidateCondition_InvalidChild(t *testing.T) {
	cond := `{"all":[{"attr":"subject.role","op":"unknownop","value":"admin"}]}`
	if err := validateCondition(json.RawMessage(cond)); err == nil {
		t.Error("invalid child node must fail validation")
	}
}

// Cross-namespace bag

func TestEvaluateCondition_CrossNamespace(t *testing.T) {
	b := AttributeBag{
		"subject":  map[string]any{"role": "admin"},
		"resource": map[string]any{"type": "document"},
		"context":  map[string]any{"ip": "10.0.0.1"},
	}
	cond := `{"all":[
		{"attr":"subject.role","op":"eq","value":"admin"},
		{"attr":"resource.type","op":"eq","value":"document"},
		{"attr":"context.ip","op":"prefix","value":"10."}
	]}`
	if !eval(t, cond, b) {
		t.Error("cross-namespace all should be true when all conditions hold")
	}
}

// TestLocksOutAuthor checks that an enabled deny refusing its own author
// policy.write is refused at save, since nobody could then remove it, while a
// deny aimed elsewhere, a disabled one, or an allow is not.
func TestLocksOutAuthor(t *testing.T) {
	author, other, tenantID := uuid.New(), uuid.New(), uuid.New()
	actor := audit.Actor{UserID: &author}
	subjectIs := func(id uuid.UUID) json.RawMessage {
		return json.RawMessage(`{"attr":"subject.id","op":"eq","value":"` + id.String() + `"}`)
	}
	for _, tc := range []struct {
		name                         string
		effect, resourceType, action string
		enabled                      bool
		cond                         json.RawMessage
		want                         bool
	}{
		{"deny everything for everyone", "deny", "*", "*", true, json.RawMessage(`{}`), true},
		{"deny policy writes for everyone", "deny", "policy", "write", true, json.RawMessage(`{}`), true},
		{"deny everything for the author", "deny", "*", "*", true, subjectIs(author), true},
		{"deny everything for someone else", "deny", "*", "*", true, subjectIs(other), false},
		{"deny everything for a resource's creator", "deny", "*", "*", true, json.RawMessage(creatorMayNotApprove), true},
		{"deny another resource for everyone", "deny", "doc", "*", true, json.RawMessage(`{}`), false},
		{"deny policy reads for everyone", "deny", "policy", "read", true, json.RawMessage(`{}`), false},
		{"disabled deny everything", "deny", "*", "*", false, json.RawMessage(`{}`), false},
		{"allow everything", "allow", "*", "*", true, json.RawMessage(`{}`), false},
	} {
		if got := locksOutAuthor(tc.effect, tc.resourceType, tc.action, tc.enabled, tc.cond, tenantID, actor); got != tc.want {
			t.Errorf("%s: locksOutAuthor = %v, want %v", tc.name, got, tc.want)
		}
	}
	if locksOutAuthor("deny", "*", "*", true, json.RawMessage(`{}`), tenantID, audit.Actor{}) {
		t.Error("a save with no user author (system) is never a lock-out")
	}
}

// Comparing two attributes: {"attr": ..., "value": {"attr": ...}}.

// The console's attribute-comparing templates, as it sends them.
const (
	regionScoped         = `{"all":[{"attr":"subject.region","op":"eq","value":{"attr":"resource.region"}}]}`
	careTeam             = `{"all":[{"attr":"subject.role","op":"eq","value":"clinician"},{"attr":"subject.care_team_ids","op":"contains","value":{"attr":"resource.patient_id"}}]}`
	creatorMayNotApprove = `{"all":[{"attr":"subject.id","op":"eq","value":{"attr":"resource.created_by"}}]}`
	clearance            = `{"all":[{"attr":"subject.clearance_level","op":"gte","value":{"attr":"resource.classification_level"}}]}`
	approversApprove     = `{"attr":"subject.role","op":"eq","value":"approver"}`
)

// refLeaf returns a leaf comparing attr with the attribute ref.
func refLeaf(attr, op, ref string) string {
	return `{"attr":"` + attr + `","op":"` + op + `","value":{"attr":"` + ref + `"}}`
}

// truthIn evaluates cond against b, failing t on an error.
func truthIn(t *testing.T, cond string, b AttributeBag) truth {
	t.Helper()
	got, err := evaluateNode(json.RawMessage(cond), b)
	if err != nil {
		t.Fatalf("%s: %v", cond, err)
	}
	return got
}

// TestEvaluateCondition_Reference checks each operator that may reference an
// attribute compares the two values as it compares an attribute with a literal.
func TestEvaluateCondition_Reference(t *testing.T) {
	b := AttributeBag{
		"subject": {
			"region": "emea", "level": float64(3), "level_text": "5", "email": "ana@qeet.in",
			"team": []any{"p1", "p2"}, "ids": []any{float64(1), float64(2)}, "groups": []any{"a", "b"},
		},
		"resource": {
			"region": "emea", "other_region": "apac", "level": 3, "low": float64(2), "high": float64(4),
			"patient": "p2", "stranger": "p9", "id_num": float64(2), "domain": "qeet.in",
			"regions": []any{"apac", "emea"}, "apac_only": []any{"apac"}, "groups": []any{"a", "b"},
		},
		"context": {"region": "emea"},
	}
	for _, tc := range []struct {
		attr, op, ref string
		want          truth
	}{
		{"subject.region", "eq", "resource.region", isTrue},
		{"subject.region", "eq", "resource.other_region", isFalse},
		{"context.region", "eq", "subject.region", isTrue},
		{"subject.level", "eq", "resource.level", isTrue}, // float64 against int
		{"subject.groups", "eq", "resource.groups", isTrue},
		{"subject.region", "ne", "resource.other_region", isTrue},
		{"subject.region", "ne", "resource.region", isFalse},
		{"subject.level", "gt", "resource.low", isTrue},
		{"subject.level", "gt", "resource.level", isFalse},
		{"subject.level", "gte", "resource.level", isTrue},
		{"subject.level", "gte", "resource.high", isFalse},
		{"subject.level_text", "gte", "resource.low", isFalse}, // a numeric string is not a number
		{"subject.level", "lt", "resource.high", isTrue},
		{"subject.level", "lt", "resource.level", isFalse},
		{"subject.level", "lte", "resource.level", isTrue},
		{"subject.level", "lte", "resource.low", isFalse},
		{"subject.region", "in", "resource.regions", isTrue},
		{"subject.region", "in", "resource.apac_only", isFalse},
		{"subject.region", "nin", "resource.apac_only", isTrue},
		{"subject.region", "nin", "resource.regions", isFalse},
		{"subject.team", "contains", "resource.patient", isTrue},
		{"subject.team", "contains", "resource.stranger", isFalse},
		{"subject.ids", "contains", "resource.id_num", isTrue},
		{"subject.email", "contains", "resource.domain", isTrue},
		{"subject.email", "contains", "resource.other_region", isFalse},
	} {
		if got := truthIn(t, refLeaf(tc.attr, tc.op, tc.ref), b); got != tc.want {
			t.Errorf("%s %s %s: got %v, want %v", tc.attr, tc.op, tc.ref, got, tc.want)
		}
	}

	// As with a literal, in and nin need an array.
	if _, err := evaluateNode(json.RawMessage(refLeaf("subject.region", "in", "resource.region")), b); err == nil {
		t.Error("in against a referenced non-array must be a condition error")
	}
	// Two arrays compare without panicking, as a literal array does.
	if !eval(t, `{"attr":"subject.groups","op":"eq","value":["a","b"]}`, b) {
		t.Error("eq: an array attribute must equal the same literal array")
	}
}

// TestEvaluateCondition_Reference_Missing checks a comparison with an absent or
// null attribute, on either side, is unknown for every operator: it never lets
// an allow apply and always lets a deny apply.
func TestEvaluateCondition_Reference_Missing(t *testing.T) {
	for _, op := range []string{"eq", "ne", "gt", "gte", "lt", "lte", "in", "nin", "contains"} {
		cond := refLeaf("subject.x", op, "resource.y")
		for name, b := range map[string]AttributeBag{
			"referenced attribute absent": {"subject": {"x": "v"}, "resource": {}},
			"referenced attribute null":   {"subject": {"x": "v"}, "resource": {"y": nil}},
			"referenced namespace absent": {"subject": {"x": "v"}},
			"compared attribute absent":   {"subject": {}, "resource": {"y": []any{"v"}}},
			"compared attribute null":     {"subject": {"x": nil}, "resource": {"y": []any{"v"}}},
		} {
			if got := truthIn(t, cond, b); got != isUnknown {
				t.Errorf("%s, %s: got %v, want unknown", op, name, got)
			}
			if allow, err := EvaluateCondition(json.RawMessage(cond), "allow", b); allow || err != nil {
				t.Errorf("%s, %s: an allow applies (%v, %v)", op, name, allow, err)
			}
			if deny, err := EvaluateCondition(json.RawMessage(cond), "deny", b); !deny || err != nil {
				t.Errorf("%s, %s: a deny does not apply (%v, %v)", op, name, deny, err)
			}
		}
	}
}

// TestEvaluateCondition_Unknown_Combines checks all, any and not carry an
// unknown comparison unless another child decides the node.
func TestEvaluateCondition_Unknown_Combines(t *testing.T) {
	b := AttributeBag{"subject": {"region": "emea", "role": "rep"}, "resource": {}}
	unknown := refLeaf("subject.region", "eq", "resource.region")
	yes := `{"attr":"subject.role","op":"eq","value":"rep"}`
	no := `{"attr":"subject.role","op":"eq","value":"admin"}`
	for _, tc := range []struct {
		cond string
		want truth
	}{
		{`{"not":` + unknown + `}`, isUnknown},
		{`{"all":[` + yes + `,` + unknown + `]}`, isUnknown},
		{`{"all":[` + unknown + `,` + no + `]}`, isFalse},
		{`{"any":[` + unknown + `,` + yes + `]}`, isTrue},
		{`{"any":[` + no + `,` + unknown + `]}`, isUnknown},
		{`{"not":{"any":[` + no + `,` + unknown + `]}}`, isUnknown},
	} {
		if got := truthIn(t, tc.cond, b); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.cond, got, tc.want)
		}
	}
}

// TestEvaluateCondition_ReferenceLookAlikeIsLiteral checks a string value that
// names an attribute is still compared as text.
func TestEvaluateCondition_ReferenceLookAlikeIsLiteral(t *testing.T) {
	for _, cond := range []string{
		`{"attr":"subject.region","op":"eq","value":"resource.region"}`,
		`{"attr":"subject.region","op":"in","value":["resource.region"]}`,
	} {
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
		if eval(t, cond, AttributeBag{"subject": {"region": "emea"}, "resource": {"region": "emea"}}) {
			t.Errorf("%s: matched the attribute it names", cond)
		}
		if !eval(t, cond, AttributeBag{"subject": {"region": "resource.region"}}) {
			t.Errorf("%s: did not match its text", cond)
		}
	}
}

// TestValidateCondition_Reference checks a well-formed reference saves on each
// operator that allows one, and a malformed one is refused at save and fails
// to evaluate.
func TestValidateCondition_Reference(t *testing.T) {
	for _, cond := range []string{
		refLeaf("subject.x", "eq", "resource.y"), refLeaf("subject.x", "ne", "context.y"),
		refLeaf("subject.x", "gt", "resource.y"), refLeaf("subject.x", "gte", "resource.y"),
		refLeaf("subject.x", "lt", "resource.y"), refLeaf("subject.x", "lte", "resource.y"),
		refLeaf("subject.x", "in", "resource.y"), refLeaf("subject.x", "nin", "resource.y"),
		refLeaf("subject.x", "contains", "resource.y"), refLeaf("resource.x", "eq", "subject.x"),
		refLeaf("subject.x", "eq", "context.geo.country"),
		regionScoped, careTeam, creatorMayNotApprove, clearance,
	} {
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
	}

	bag := AttributeBag{"subject": {"region": "emea", "email": "a@b"}, "resource": {"region": "emea"}}
	for name, cond := range map[string]string{
		"extra key":           `{"attr":"subject.region","op":"eq","value":{"attr":"resource.region","default":"emea"}}`,
		"empty object":        `{"attr":"subject.region","op":"eq","value":{}}`,
		"wrong key":           `{"attr":"subject.region","op":"eq","value":{"Attr":"resource.region"}}`,
		"non-string":          `{"attr":"subject.region","op":"eq","value":{"attr":5}}`,
		"null":                `{"attr":"subject.region","op":"eq","value":{"attr":null}}`,
		"empty":               refLeaf("subject.region", "eq", ""),
		"no namespace":        refLeaf("subject.region", "eq", "region"),
		"unknown namespace":   refLeaf("subject.region", "eq", "tenant.region"),
		"empty path":          refLeaf("subject.region", "eq", "resource."),
		"empty segment":       refLeaf("subject.region", "eq", "resource..region"),
		"own attribute":       refLeaf("subject.region", "eq", "subject.region"),
		"regex":               refLeaf("subject.email", "regex", "resource.region"),
		"prefix":              refLeaf("subject.email", "prefix", "resource.region"),
		"suffix":              refLeaf("subject.email", "suffix", "resource.region"),
		"exists":              refLeaf("subject.email", "exists", "resource.region"),
		"nested":              `{"all":[{"not":` + refLeaf("subject.region", "eq", "tenant.region") + `}]}`,
		"in an array element": `{"attr":"subject.region","op":"nin","value":[{"attr":"resource.region"}]}`,
	} {
		if err := validateCondition(json.RawMessage(cond)); err == nil {
			t.Errorf("%s: saved %s", name, cond)
		}
		if name == "in an array element" {
			continue // refused at save only: evaluated, it is a literal object
		}
		if _, err := EvaluateCondition(json.RawMessage(cond), "allow", bag); err == nil {
			t.Errorf("%s: evaluated %s without an error", name, cond)
		}
	}
}

// TestCombine_Templates evaluates the console's attribute-comparing templates
// as stored policies, through the same combining step as the evaluate API.
func TestCombine_Templates(t *testing.T) {
	policy := func(name, effect, cond string) candidate {
		return candidate{id: uuid.New(), name: name, effect: effect, condition: []byte(cond)}
	}
	region := policy("sfdc_region_scoped_accounts", "allow", regionScoped)
	phi := policy("phi_care_team_read", "allow", careTeam)
	sod := policy("sox_payment_sod", "deny", creatorMayNotApprove)
	approvers := policy("approvers_approve", "allow", approversApprove)
	gov := policy("gov_clearance_gate", "allow", clearance)
	for _, p := range []candidate{region, phi, sod, approvers, gov} {
		if err := validateCondition(p.condition); err != nil {
			t.Fatalf("%s does not save: %v", p.name, err)
		}
	}

	team := []any{"p1", "p2"}
	for _, tc := range []struct {
		name              string
		policies          []candidate
		subject, resource map[string]any
		by                *candidate // the policy that decides; nil for the default deny
		allow             bool
	}{
		{"rep reads an account in their region", []candidate{region}, map[string]any{"region": "emea"}, map[string]any{"region": "emea"}, &region, true},
		{"rep reads an account in another region", []candidate{region}, map[string]any{"region": "emea"}, map[string]any{"region": "apac"}, nil, false},
		{"account has no region", []candidate{region}, map[string]any{"region": "emea"}, nil, nil, false},
		{"rep has no region", []candidate{region}, nil, map[string]any{"region": "emea"}, nil, false},

		{"clinician reads a patient on their care team", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p2"}, &phi, true},
		{"clinician reads a patient off their care team", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, map[string]any{"patient_id": "p9"}, nil, false},
		{"non-clinician on the care team", []candidate{phi}, map[string]any{"role": "billing", "care_team_ids": team}, map[string]any{"patient_id": "p2"}, nil, false},
		{"record names no patient", []candidate{phi}, map[string]any{"role": "clinician", "care_team_ids": team}, nil, nil, false},
		{"clinician has no care team", []candidate{phi}, map[string]any{"role": "clinician"}, map[string]any{"patient_id": "p2"}, nil, false},

		{"creator approves their own payment", []candidate{sod, approvers}, map[string]any{"id": "u1", "role": "approver"}, map[string]any{"created_by": "u1"}, &sod, false},
		{"another approver approves it", []candidate{sod, approvers}, map[string]any{"id": "u2", "role": "approver"}, map[string]any{"created_by": "u1"}, &approvers, true},
		{"payment's creator is unknown", []candidate{sod, approvers}, map[string]any{"id": "u2", "role": "approver"}, nil, &sod, false},
		{"approver's id is unknown", []candidate{sod, approvers}, map[string]any{"role": "approver"}, map[string]any{"created_by": "u1"}, &sod, false},
		{"another user, and no allow policy", []candidate{sod}, map[string]any{"id": "u2"}, map[string]any{"created_by": "u1"}, nil, false},

		{"clearance above the classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": float64(2)}, &gov, true},
		{"clearance at the classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": float64(3)}, &gov, true},
		{"clearance below the classification", []candidate{gov}, map[string]any{"clearance_level": float64(2)}, map[string]any{"classification_level": float64(3)}, nil, false},
		{"document has no classification", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, nil, nil, false},
		{"classification sent as text", []candidate{gov}, map[string]any{"clearance_level": float64(3)}, map[string]any{"classification_level": "2"}, nil, false},
	} {
		dec := combine(tc.policies, attributeBag(EvaluationInput{
			Subject:  tc.subject,
			Resource: EvaluationResource{Type: "record", ID: "r1", Attrs: tc.resource},
			Action:   "act",
		}))
		if dec.Allow != tc.allow {
			t.Errorf("%s: allow = %v, want %v (%s)", tc.name, dec.Allow, tc.allow, dec.Reason)
		}
		switch {
		case tc.by == nil && dec.MatchedPolicyID != nil:
			t.Errorf("%s: decided by policy %s, want the default deny", tc.name, dec.MatchedPolicyID)
		case tc.by != nil && (dec.MatchedPolicyID == nil || *dec.MatchedPolicyID != tc.by.id):
			t.Errorf("%s: decided by %v, want %s (%s)", tc.name, dec.MatchedPolicyID, tc.by.name, dec.Reason)
		}
	}

	dec := combine([]candidate{sod, approvers}, attributeBag(EvaluationInput{Subject: map[string]any{"id": "u2", "role": "approver"}}))
	if !strings.Contains(dec.Reason, "absent") || !strings.Contains(strings.Join(dec.Trace, "\n"), "absent → deny") {
		t.Errorf("a deny applied for an absent attribute must say so: %q %q", dec.Reason, dec.Trace)
	}
}

// TestPrefixSuffix_NeedAStringValue checks prefix and suffix without a
// non-empty string value are refused at save, and that a stored one fails
// closed, so an allow grants nothing and a deny still denies, even beside an
// allow for everyone. A non-string attribute matches neither effect.
func TestPrefixSuffix_NeedAStringValue(t *testing.T) {
	b := resourceBag(map[string]any{"name": "prod-api", "size": float64(5)})
	allowAll := candidate{id: uuid.New(), name: "allow_all", effect: "allow", condition: []byte(`{}`)}
	for _, op := range []string{"prefix", "suffix"} {
		for _, value := range []string{`""`, `5`, `true`, `null`, `["prod-"]`, ``} {
			cond := `{"attr":"resource.name","op":"` + op + `","value":` + value + `}`
			if value == `` {
				cond = `{"attr":"resource.name","op":"` + op + `"}`
			}
			if err := validateCondition(json.RawMessage(cond)); err == nil {
				t.Errorf("saved %s", cond)
			}
			for _, effect := range []string{"allow", "deny"} {
				bad := candidate{id: uuid.New(), name: "bad", effect: effect, condition: []byte(cond)}
				dec := combine([]candidate{bad, allowAll}, b)
				if dec.Allow || dec.MatchedPolicyID == nil || *dec.MatchedPolicyID != bad.id {
					t.Errorf("%s %s: allow %v by %v, want a fail-closed deny by the policy", effect, cond, dec.Allow, dec.MatchedPolicyID)
				}
			}
		}

		cond := `{"attr":"resource.size","op":"` + op + `","value":"5"}`
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
		if eval(t, cond, b) {
			t.Errorf("%s: a non-string attribute matched", cond)
		}
	}
}

// TestEmptyContainsAndRegexFailClosed checks that looking for "" with
// contains, or matching an empty pattern, which every string would satisfy, is
// refused on save and denies when it is stored or reached through a reference.
func TestEmptyContainsAndRegexFailClosed(t *testing.T) {
	b := resourceBag(map[string]any{"name": "prod-api", "owner": ""})
	allowAll := candidate{id: uuid.New(), name: "allow_all", effect: "allow", condition: []byte(`{}`)}
	for _, cond := range []string{
		`{"attr":"resource.name","op":"contains","value":""}`,
		`{"attr":"resource.name","op":"regex","value":""}`,
	} {
		if err := validateCondition(json.RawMessage(cond)); err == nil {
			t.Errorf("saved %s", cond)
		}
	}
	for _, cond := range []string{
		`{"attr":"resource.name","op":"contains","value":""}`,
		`{"attr":"resource.name","op":"regex","value":""}`,
		`{"attr":"resource.name","op":"contains","value":{"attr":"resource.owner"}}`,
	} {
		for _, effect := range []string{"allow", "deny"} {
			bad := candidate{id: uuid.New(), name: "bad", effect: effect, condition: []byte(cond)}
			dec := combine([]candidate{bad, allowAll}, b)
			if dec.Allow || dec.MatchedPolicyID == nil || *dec.MatchedPolicyID != bad.id {
				t.Errorf("%s %s: allow %v by %v, want a fail-closed deny by the policy", effect, cond, dec.Allow, dec.MatchedPolicyID)
			}
		}
	}
	for _, cond := range []string{
		`{"attr":"resource.name","op":"contains","value":"prod"}`,
		`{"attr":"resource.name","op":"regex","value":"^prod-"}`,
	} {
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
		if !eval(t, cond, b) {
			t.Errorf("%s: did not match", cond)
		}
	}
}

// TestDecisionReasonCodes checks that each kind of decision carries its reason
// code and names the policy that decided, and that a condition error names the
// policy without the evaluation error.
func TestDecisionReasonCodes(t *testing.T) {
	b := resourceBag(map[string]any{"name": "prod-api"})
	allow := candidate{id: uuid.New(), name: "allow_prod", effect: "allow", priority: 5, condition: []byte(`{"attr":"resource.name","op":"prefix","value":"prod-"}`)}
	deny := candidate{id: uuid.New(), name: "deny_prod", effect: "deny", priority: 9, condition: []byte(`{"attr":"resource.name","op":"prefix","value":"prod-"}`)}
	absent := candidate{id: uuid.New(), name: "deny_owner", effect: "deny", priority: 7, condition: []byte(`{"attr":"resource.owner","op":"eq","value":{"attr":"subject.id"}}`)}
	broken := candidate{id: uuid.New(), name: "broken", effect: "allow", priority: 3, condition: []byte(`{"attr":"resource.name","op":"bogus","value":"x"}`)}
	for _, tc := range []struct {
		name     string
		policies []candidate
		code     string
		by       *candidate
	}{
		{"an allow policy matches", []candidate{allow}, ReasonAllowedByPolicy, &allow},
		{"a deny policy matches", []candidate{deny, allow}, ReasonDeniedByPolicy, &deny},
		{"a deny compares an absent attribute", []candidate{absent}, ReasonAttributeAbsent, &absent},
		{"a condition fails to evaluate", []candidate{broken}, ReasonConditionError, &broken},
		{"nothing matches", nil, ReasonNoMatchingAllow, nil},
	} {
		dec := combine(tc.policies, b)
		if dec.ReasonCode != tc.code {
			t.Errorf("%s: reason code %q, want %q", tc.name, dec.ReasonCode, tc.code)
		}
		var want map[string]any
		if tc.by != nil {
			want = map[string]any{"policy_id": tc.by.id, "policy_name": tc.by.name, "priority": tc.by.priority}
		}
		if fmt.Sprint(dec.ReasonParams) != fmt.Sprint(want) {
			t.Errorf("%s: reason params %v, want %v", tc.name, dec.ReasonParams, want)
		}
	}

	dec := combine([]candidate{broken}, b)
	if shown := dec.Reason + strings.Join(dec.Trace, "\n"); strings.Contains(shown, "unknown operator") || strings.Contains(shown, "bogus") {
		t.Errorf("a condition error showed its evaluation error: %q", shown)
	}
}
