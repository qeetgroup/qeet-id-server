package abac

import (
	"encoding/json"
	"testing"
)

func TestEvaluateCondition_EmptyIsTrue(t *testing.T) {
	if !eval(t, `{}`, AttributeBag{}) {
		t.Error("empty condition must always be true")
	}
	if !eval(t, `null`, AttributeBag{}) {
		t.Error("null condition must always be true")
	}
}

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

func TestEvaluateCondition_Exists(t *testing.T) {
	b := subjectBag(map[string]any{"email": "alice@example.com"})
	if !eval(t, `{"attr":"subject.email","op":"exists"}`, b) {
		t.Error("exists: present attr should be true")
	}
	if eval(t, `{"attr":"subject.phone","op":"exists"}`, b) {
		t.Error("exists: absent attr should be false")
	}
}

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

// TestEvaluateCondition_MissingAttr_Unknown checks that comparing an absent or
// null attribute with a literal is unknown for every operator, ne and nin
// included: an allow never applies, so grants nothing, and a deny always does.
func TestEvaluateCondition_MissingAttr_Unknown(t *testing.T) {
	for _, op := range []string{"eq", "ne", "gt", "gte", "lt", "lte", "contains", "prefix", "suffix", "regex", "in", "nin"} {
		val := `"anything"`
		if op == "in" || op == "nin" {
			val = `["a","b"]`
		}
		cond := `{"attr":"subject.x","op":"` + op + `","value":` + val + `}`
		for name, b := range map[string]AttributeBag{
			"attribute absent": {"subject": {}},
			"attribute null":   {"subject": {"x": nil}},
			"namespace absent": {"resource": {"x": "anything"}},
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

// TestEvaluateCondition_MissingAttr_Exists checks that exists, which tests
// presence, stays known: false for an absent attribute, true for a null one.
func TestEvaluateCondition_MissingAttr_Exists(t *testing.T) {
	if eval(t, `{"attr":"subject.missing","op":"exists"}`, AttributeBag{"subject": {}}) {
		t.Error("exists on absent attr must be false")
	}
	if !eval(t, `{"attr":"subject.x","op":"exists"}`, AttributeBag{"subject": {"x": nil}}) {
		t.Error("exists on a null attr must be true")
	}
}

// TestEvaluateCondition_MissingAttr_Negated checks that negating a comparison
// with a missing attribute still decides nothing, so "not a contractor" grants
// nothing to someone whose department is unknown, and that exists guards a
// deny meant only for requests that carry the attribute.
func TestEvaluateCondition_MissingAttr_Negated(t *testing.T) {
	b := AttributeBag{"subject": {"id": "u1"}, "resource": {}}
	notContractor := `{"not":{"attr":"subject.department","op":"eq","value":"contractors"}}`
	if allow, _ := EvaluateCondition(json.RawMessage(notContractor), "allow", b); allow {
		t.Error("an allow on a negated comparison applied to an absent attribute")
	}
	if deny, _ := EvaluateCondition(json.RawMessage(notContractor), "deny", b); !deny {
		t.Error("a deny on a negated comparison did not apply to an absent attribute")
	}
	guarded := `{"all":[{"attr":"resource.classification","op":"exists"},{"attr":"resource.classification","op":"eq","value":"secret"}]}`
	if deny, _ := EvaluateCondition(json.RawMessage(guarded), "deny", b); deny {
		t.Error("a deny guarded by exists applied without the attribute")
	}
	if deny, _ := EvaluateCondition(json.RawMessage(guarded), "deny", AttributeBag{"resource": {"classification": "secret"}}); !deny {
		t.Error("a deny guarded by exists did not apply with the attribute")
	}
}

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

// FuzzEvaluateCondition feeds arbitrary condition trees to the evaluator. It must never panic, a
// tree that fails to evaluate never applies (fail closed), and a tree the API would store
// (validateCondition accepts it) always evaluates, so a saved policy can't fail at decision time.
func FuzzEvaluateCondition(f *testing.F) {
	for _, seed := range []string{
		`{}`, `null`, ``, `[]`, `{"attr":"subject.dept","op":"eq","value":"eng"}`,
		`{"all":[{"any":[{"attr":"subject.role","op":"eq","value":"admin"}]},{"not":{"attr":"subject.suspended","op":"eq","value":true}}]}`,
		`{"all":[{"attr":"resource.classification","op":"exists"},{"attr":"resource.classification","op":"eq","value":"secret"}]}`,
		`{"attr":"context.hour","op":"gte","value":9}`, `{"attr":"context.score","op":"lt","value":0.3}`,
		`{"attr":"resource.name","op":"contains","value":{"attr":"resource.owner"}}`,
		`{"attr":"resource.name","op":"regex","value":"^prod-"}`, `{"attr":"subject.role","op":"in","value":["admin","owner"]}`,
		`{"all":[{"attr":"subject.role","op":"unknownop","value":"admin"}]}`, `{"not":{"not":{"not":{}}}}`,
	} {
		f.Add(seed)
	}
	bag := AttributeBag{
		"subject":  {"dept": "eng", "role": "admin", "level": float64(3), "suspended": false},
		"resource": {"name": "prod-db", "owner": "u1", "classification": "secret"},
		"action":   {"name": "read"},
		"context":  {"hour": float64(10), "score": 0.2, "mfa": true},
	}
	f.Fuzz(func(t *testing.T, raw string) {
		valid := validateCondition(json.RawMessage(raw)) == nil
		for _, effect := range []string{"allow", "deny"} {
			if applies, err := EvaluateCondition(json.RawMessage(raw), effect, bag); err != nil && applies {
				t.Fatalf("%s policy %q applies although it failed to evaluate: %v", effect, raw, err)
			}
			if !valid {
				continue
			}
			if _, err := EvaluateCondition(json.RawMessage(raw), effect, AttributeBag{}); err != nil {
				t.Fatalf("condition %q passes validation but fails to evaluate: %v", raw, err)
			}
		}
	})
}
