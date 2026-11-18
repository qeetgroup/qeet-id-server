package rebac

import (
	"testing"
)

func TestExpand_HonoursDepthLimit(t *testing.T) {
	m := memStore{
		"document:readme#viewer": {{subjectType: "group", subjectID: "eng", subjectRelation: "member"}},
		"group:eng#member":       {{subjectType: "group", subjectID: "core", subjectRelation: "member"}},
		"group:core#member":      {{subjectType: "user", subjectID: "erin"}},
	}
	reached := func(limit int) bool {
		nodes, _, err := expand(m.fetch, "document", "readme", "viewer", limit)
		if err != nil {
			t.Fatalf("expand: %v", err)
		}
		_, ok := nodes["user:erin"]
		return ok
	}
	if reached(1) {
		t.Error("user:erin is two userset hops away and must not appear with limit 1")
	}
	if !reached(2) {
		t.Error("user:erin should appear with limit 2")
	}
}

// TestExpand_CountsTheShortestPath checks that a subject within the limit by
// one path is reached, though a longer path gets to its group first.
func TestExpand_CountsTheShortestPath(t *testing.T) {
	m := memStore{
		"document:readme#viewer": {
			{subjectType: "group", subjectID: "a", subjectRelation: "member"},
			{subjectType: "group", subjectID: "b", subjectRelation: "member"},
		},
		"group:a#member": {{subjectType: "group", subjectID: "b", subjectRelation: "member"}},
		"group:b#member": {{subjectType: "group", subjectID: "c", subjectRelation: "member"}},
		"group:c#member": {{subjectType: "user", subjectID: "x"}},
	}
	nodes, _, err := expand(m.fetch, "document", "readme", "viewer", 2)
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	if _, ok := nodes["user:x"]; !ok {
		t.Error("user:x is two userset hops away through group:b and must appear with limit 2")
	}
}
