package abac

import (
	"encoding/json"
	"testing"
)

// bag is a convenience constructor for a simple attribute bag used in tests.
func bag(ns string, attrs map[string]any) AttributeBag {
	return AttributeBag{ns: attrs}
}

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

func eval(t *testing.T, condJSON string, b AttributeBag) bool {
	t.Helper()
	ok, err := EvaluateCondition(json.RawMessage(condJSON), b)
	if err != nil {
		t.Fatalf("EvaluateCondition error: %v", err)
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
	ok, err := EvaluateCondition(json.RawMessage(`{"attr":"subject.email","op":"regex","value":"[invalid"}`), b)
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
	_, err := EvaluateCondition(json.RawMessage(`{invalid json`), AttributeBag{})
	if err == nil {
		t.Error("malformed JSON must return an error")
	}
}

func TestEvaluateCondition_UnknownOp(t *testing.T) {
	b := subjectBag(map[string]any{"x": "y"})
	_, err := EvaluateCondition(json.RawMessage(`{"attr":"subject.x","op":"superop","value":"y"}`), b)
	if err == nil {
		t.Error("unknown operator must return an error")
	}
}

func TestEvaluateCondition_UnrecognizedNode(t *testing.T) {
	_, err := EvaluateCondition(json.RawMessage(`{"bogus":"field"}`), AttributeBag{})
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
