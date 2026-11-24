package strutil

import (
	"slices"
	"testing"
)

// TestPointers checks that "" and nil stand for each other.
func TestPointers(t *testing.T) {
	if NilIfEmpty("") != nil {
		t.Error(`NilIfEmpty("") is not nil`)
	}
	if p := NilIfEmpty("a"); p == nil || *p != "a" {
		t.Errorf(`NilIfEmpty("a") = %v`, p)
	}
	if Deref(nil) != "" {
		t.Error("Deref(nil) is not empty")
	}
	if s := "b"; Deref(&s) != "b" {
		t.Error(`Deref(&"b") is not "b"`)
	}
}

// TestTruncate checks that only a longer string is cut.
func TestTruncate(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{{"abcdef", 3, "abc"}, {"abc", 3, "abc"}, {"ab", 3, "ab"}, {"", 0, ""}} {
		if got := Truncate(c.in, c.n); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// TestSplitList checks that entries are trimmed and empty ones dropped.
func TestSplitList(t *testing.T) {
	if got := SplitList(" a, b ,,c ,"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("SplitList = %q", got)
	}
	for _, raw := range []string{"", " ", " , ,"} {
		if got := SplitList(raw); got != nil {
			t.Errorf("SplitList(%q) = %q, want nil", raw, got)
		}
	}
}
