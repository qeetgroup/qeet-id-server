package rebac

import "testing"

// memStore is an in-memory tuple set keyed by "objType:objID#relation".
type memStore map[string][]tuple

func (m memStore) fetch(objType, objID, relation string) ([]tuple, error) {
	return m[objType+":"+objID+"#"+relation], nil
}

func check(m memStore, objType, objID, relation, userID string) bool {
	ok, _ := resolve(m.fetch, objType, objID, relation, userID, map[string]bool{}, 0)
	return ok
}

func TestResolve_Direct(t *testing.T) {
	m := memStore{
		"document:readme#editor": {{subjectType: "user", subjectID: "alice"}},
	}
	if !check(m, "document", "readme", "editor", "alice") {
		t.Error("alice should be a direct editor")
	}
	if check(m, "document", "readme", "editor", "bob") {
		t.Error("bob is not an editor")
	}
}

func TestResolve_Userset(t *testing.T) {
	m := memStore{
		// viewers of the doc = members of group:eng
		"document:readme#viewer": {{subjectType: "group", subjectID: "eng", subjectRelation: "member"}},
		// group:eng members
		"group:eng#member": {{subjectType: "user", subjectID: "carol"}},
	}
	if !check(m, "document", "readme", "viewer", "carol") {
		t.Error("carol (group:eng#member) should be a viewer via the userset")
	}
	if check(m, "document", "readme", "viewer", "dave") {
		t.Error("dave is not in group:eng, must not be a viewer")
	}
}

func TestResolve_NestedUserset(t *testing.T) {
	m := memStore{
		"document:readme#viewer": {{subjectType: "group", subjectID: "all", subjectRelation: "member"}},
		// nested: group:all members include the group:eng userset
		"group:all#member": {{subjectType: "group", subjectID: "eng", subjectRelation: "member"}},
		"group:eng#member": {{subjectType: "user", subjectID: "erin"}},
	}
	if !check(m, "document", "readme", "viewer", "erin") {
		t.Error("erin should resolve through nested usersets all→eng")
	}
}

func TestResolve_CycleGuard(t *testing.T) {
	// group:a#member references group:b#member and vice versa — must terminate.
	m := memStore{
		"group:a#member": {{subjectType: "group", subjectID: "b", subjectRelation: "member"}},
		"group:b#member": {{subjectType: "group", subjectID: "a", subjectRelation: "member"}},
	}
	if check(m, "group", "a", "member", "nobody") {
		t.Error("cycle must resolve to false, not loop")
	}
}

func TestParseSubject(t *testing.T) {
	if s, ok := parseSubject("user:abc"); !ok || s.Type != "user" || s.ID != "abc" || s.Relation != "" {
		t.Errorf("direct user parse failed: %+v ok=%v", s, ok)
	}
	if s, ok := parseSubject("group:eng#member"); !ok || s.Type != "group" || s.ID != "eng" || s.Relation != "member" {
		t.Errorf("userset parse failed: %+v ok=%v", s, ok)
	}
	if _, ok := parseSubject("nocolon"); ok {
		t.Error("malformed subject must fail")
	}
}
