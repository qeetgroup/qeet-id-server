package abac

import (
	"encoding/json"
	"testing"
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

// eq / ne

// in / nin

// contains

// Numeric comparisons: gt, gte, lt, lte

// exists

// prefix / suffix

// regex

// Logical gates: all, any, not

// Nested conditions

// Missing / absent attributes

// Multi-segment nested attribute path

// Malformed JSON → error (fail-closed at caller)

// validateCondition

// Cross-namespace bag

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
