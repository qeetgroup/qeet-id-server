package agent

import (
	"testing"
)

func TestValidateTransition(t *testing.T) {
	ok := []struct{ cur, target string }{
		{"active", "suspended"},              // suspend
		{"suspended", "active"},              // resume
		{"active", "decommissioned"},         // decommission from active
		{"suspended", "decommissioned"},      // decommission from suspended
		{"active", "active"},                 // idempotent
		{"suspended", "suspended"},           // idempotent
		{"decommissioned", "decommissioned"}, // idempotent (terminal, no change)
	}
	for _, c := range ok {
		if err := validateTransition(c.cur, c.target); err != nil {
			t.Errorf("validateTransition(%q, %q) = %v, want nil", c.cur, c.target, err)
		}
	}
	bad := []struct{ cur, target string }{
		{"decommissioned", "active"},    // terminal — cannot resurrect
		{"decommissioned", "suspended"}, // terminal
		{"active", "bogus"},             // invalid target
	}
	for _, c := range bad {
		if err := validateTransition(c.cur, c.target); err == nil {
			t.Errorf("validateTransition(%q, %q) = nil, want error", c.cur, c.target)
		}
	}
}
