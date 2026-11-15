package paging

import "testing"

// TestList checks that a list over the cap is cut to it and marked truncated,
// and that one within it is left alone.
func TestList(t *testing.T) {
	short := List(make([]int, MaxListItems))
	if len(short["items"].([]int)) != MaxListItems || short["truncated"] != nil {
		t.Errorf("a list at the cap: %d items, truncated %v", len(short["items"].([]int)), short["truncated"])
	}
	long := List(make([]int, MaxListItems+1))
	if len(long["items"].([]int)) != MaxListItems || long["truncated"] != true {
		t.Errorf("a list over the cap: %d items, truncated %v", len(long["items"].([]int)), long["truncated"])
	}
}

// TestListWith checks that the other fields sit beside the cut items.
func TestListWith(t *testing.T) {
	body := ListWith(make([]int, MaxListItems+1), map[string]any{"enabled": true})
	if len(body["items"].([]int)) != MaxListItems || body["truncated"] != true || body["enabled"] != true {
		t.Errorf("body = %d items, truncated %v, enabled %v", len(body["items"].([]int)), body["truncated"], body["enabled"])
	}
}
