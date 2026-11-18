package abac

import (
	"encoding/json"
	"testing"
)

// TestAttributeBag checks that the action's name and attributes form the
// action namespace, that a reference may name it, and that an attribute named
// type, id or name never replaces the resource or action decided on.
func TestAttributeBag(t *testing.T) {
	b := attributeBag(EvaluationInput{
		Resource:    EvaluationResource{Type: "document", ID: "d1", Attrs: map[string]any{"type": "invoice", "id": "x", "owner": "u1"}},
		Action:      "read",
		ActionAttrs: map[string]any{"name": "delete", "channel": "api"},
		Subject:     map[string]any{"id": "u1", "channel": "api"},
	})
	for cond, want := range map[string]bool{
		`{"attr":"resource.type","op":"eq","value":"document"}`:                  true,
		`{"attr":"resource.id","op":"eq","value":"d1"}`:                          true,
		`{"attr":"resource.owner","op":"eq","value":"u1"}`:                       true,
		`{"attr":"action.name","op":"eq","value":"read"}`:                        true,
		`{"attr":"action.channel","op":"eq","value":"api"}`:                      true,
		`{"attr":"subject.channel","op":"eq","value":{"attr":"action.channel"}}`: true,
	} {
		if err := validateCondition(json.RawMessage(cond)); err != nil {
			t.Errorf("%s: %v", cond, err)
		}
		if got := eval(t, cond, b); got != want {
			t.Errorf("%s: %v, want %v", cond, got, want)
		}
	}
}
