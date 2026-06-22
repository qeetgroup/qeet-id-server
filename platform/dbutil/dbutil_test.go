package dbutil_test

import (
	"testing"

	"github.com/qeetgroup/qeet-id/platform/dbutil"
)

func TestUpdateBuilder(t *testing.T) {
	ub := dbutil.NewUpdate()
	if !ub.Empty() {
		t.Fatal("new builder should be empty")
	}
	ub.Set("name", "acme")
	ub.Set("plan", "pro")
	if ub.Empty() {
		t.Fatal("should not be empty after Set")
	}
	ub.SetRaw("updated_at = NOW()")

	if got, want := ub.Assignments(), "name = $1, plan = $2, updated_at = NOW()"; got != want {
		t.Errorf("Assignments() = %q, want %q", got, want)
	}
	// SetRaw binds no value, so the next placeholder stays after the 2 Sets.
	if got := ub.NextPlaceholder(); got != 3 {
		t.Errorf("NextPlaceholder() = %d, want 3", got)
	}
	args := ub.Args()
	if len(args) != 2 || args[0] != "acme" || args[1] != "pro" {
		t.Errorf("Args() = %v, want [acme pro]", args)
	}
}

func TestUpdateBuilderEmpty(t *testing.T) {
	ub := dbutil.NewUpdate()
	if !ub.Empty() {
		t.Error("should be empty")
	}
	if ub.NextPlaceholder() != 1 {
		t.Errorf("NextPlaceholder() = %d, want 1", ub.NextPlaceholder())
	}
}

func TestMetadata(t *testing.T) {
	if m := dbutil.Metadata(nil); m == nil || len(m) != 0 {
		t.Errorf("nil -> %v, want empty non-nil map", m)
	}
	if m := dbutil.Metadata([]byte(`{"a":1}`)); m["a"] != float64(1) {
		t.Errorf("decode -> %v", m)
	}
	if m := dbutil.Metadata([]byte("not json")); m == nil || len(m) != 0 {
		t.Errorf("bad json -> %v, want empty map", m)
	}
	if m := dbutil.Metadata([]byte("null")); m == nil || len(m) != 0 {
		t.Errorf("json null -> %v, want empty map", m)
	}
}
