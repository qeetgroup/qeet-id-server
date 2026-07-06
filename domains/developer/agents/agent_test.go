package agent

import (
	"strings"
	"testing"
)

func TestClampTTL(t *testing.T) {
	cases := map[int]int{
		0:    600,  // default
		-5:   600,  // default
		30:   60,   // floor
		600:  600,  // pass-through
		3600: 3600, // ceiling
		9999: 3600, // clamp to ceiling
	}
	for in, want := range cases {
		if got := clampTTL(in); got != want {
			t.Errorf("clampTTL(%d) = %d, want %d", in, got, want)
		}
	}
}

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

func TestNewSecretShape(t *testing.T) {
	a, err := newSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newSecret()
	if a == b {
		t.Error("secrets must be unique")
	}
	if !strings.HasPrefix(a, "agt_") || len(a) < 20 {
		t.Errorf("unexpected secret shape: %q", a)
	}
}
