package abac

import (
	"encoding/json"
	"testing"
)

// TestRoleAndRelationConditions checks a role condition against the roles the
// platform supplies, unknown without them, and a relation condition against
// the relationships resolved into the bag, unknown when unresolved; and that a
// malformed one is refused.
func TestRoleAndRelationConditions(t *testing.T) {
	withRoles := AttributeBag{"subject": {"id": "u1", "roles": []any{"admin", "billing"}}, "resource": {"id": "doc-1"}}
	withRelations := AttributeBag{"subject": {"id": "u1"}, "resource": {"object": "document:doc-1"},
		relationsKey: {"document:doc-1#viewer": true, "document:doc-1#owner": false}}
	for _, tc := range []struct {
		name, cond string
		bag        AttributeBag
		want       truth
	}{
		{"a role held", `{"role":"admin"}`, withRoles, isTrue},
		{"a role not held", `{"role":"auditor"}`, withRoles, isFalse},
		{"a role without the roles", `{"role":"admin"}`, AttributeBag{"subject": {"id": "u1"}}, isUnknown},
		{"a relation held", `{"relation":{"relation":"viewer","object":"document:doc-1"}}`, withRelations, isTrue},
		{"a relation not held", `{"relation":{"relation":"owner","object":"document:doc-1"}}`, withRelations, isFalse},
		{"a relation by reference", `{"relation":{"relation":"viewer","object":{"attr":"resource.object"}}}`, withRelations, isTrue},
		{"a relation unresolved", `{"relation":{"relation":"editor","object":"document:doc-1"}}`, withRelations, isUnknown},
		{"a reference to nothing", `{"relation":{"relation":"viewer","object":{"attr":"resource.missing"}}}`, withRelations, isUnknown},
		{"a role and a relation", `{"all":[{"role":"admin"},{"relation":{"relation":"viewer","object":"document:doc-1"}}]}`,
			AttributeBag{"subject": {"id": "u1", "roles": []any{"admin"}}, relationsKey: {"document:doc-1#viewer": true}}, isTrue},
	} {
		got, err := evaluateNode(json.RawMessage(tc.cond), tc.bag)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	for _, bad := range []string{`{"role":""}`, `{"role":7}`, `{"relation":{"relation":"viewer"}}`,
		`{"relation":{"relation":"","object":"document:1"}}`, `{"relation":{"relation":"viewer","object":"document"}}`,
		`{"relation":{"relation":"viewer","object":{"attr":"secrets.key"}}}`} {
		if validateCondition(json.RawMessage(bad)) == nil {
			t.Errorf("condition %s was accepted", bad)
		}
	}
}
