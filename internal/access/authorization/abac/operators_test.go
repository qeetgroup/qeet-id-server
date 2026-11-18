package abac

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

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
