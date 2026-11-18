package scim

import (
	"testing"
)

func TestStatusFromActive(t *testing.T) {
	tru, fls := true, false
	if got := statusFromActive(nil); got != "" {
		t.Errorf("nil active should leave status untouched, got %q", got)
	}
	if got := statusFromActive(&tru); got != "active" {
		t.Errorf("active=true → active, got %q", got)
	}
	if got := statusFromActive(&fls); got != "suspended" {
		t.Errorf("active=false → suspended, got %q", got)
	}
}
