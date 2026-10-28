package ssosync

import (
	"slices"
	"strings"
	"testing"
)

// TestGroupValues checks that asserted groups are matched trimmed and once
// each, leaving case to the database and dropping empty and overlong ones.
func TestGroupValues(t *testing.T) {
	overlong := strings.Repeat("g", maxGroupValue+1)
	got := groupValues([]string{" Engineering ", "Engineering", "engineering", "", "   ", overlong, "CN=Ops,OU=Groups,DC=corp"})
	want := []string{"Engineering", "engineering", "CN=Ops,OU=Groups,DC=corp"}
	if !slices.Equal(got, want) {
		t.Errorf("groupValues = %q, want %q", got, want)
	}
	if got := groupValues(nil); len(got) != 0 {
		t.Errorf("groupValues(nil) = %q, want none", got)
	}
}
