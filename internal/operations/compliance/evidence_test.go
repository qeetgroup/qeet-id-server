package gdpr

import (
	"testing"
)

// TestControlCatalog_SOC2 verifies the SOC 2 catalog has the expected
// number of controls and that every entry is well-formed.
func TestControlCatalog_SOC2(t *testing.T) {
	const want = 13
	if got := len(soc2Controls); got != want {
		t.Errorf("soc2Controls: got %d controls, want %d", got, want)
	}
	seen := map[string]bool{}
	for _, c := range soc2Controls {
		if c.id == "" {
			t.Errorf("control with empty id in soc2 catalog")
		}
		if c.name == "" {
			t.Errorf("control %q has empty name", c.id)
		}
		if c.criteria == "" {
			t.Errorf("control %q has empty criteria", c.id)
		}
		if c.check == nil {
			t.Errorf("control %q has nil check function", c.id)
		}
		if seen[c.id] {
			t.Errorf("duplicate control id %q in soc2 catalog", c.id)
		}
		seen[c.id] = true
	}
}

// TestControlCatalog_ISO27001 verifies the ISO 27001 catalog has the expected
// number of controls and that every entry is well-formed.
func TestControlCatalog_ISO27001(t *testing.T) {
	const want = 12
	if got := len(iso27001Controls); got != want {
		t.Errorf("iso27001Controls: got %d controls, want %d", got, want)
	}
	seen := map[string]bool{}
	for _, c := range iso27001Controls {
		if c.id == "" {
			t.Errorf("control with empty id in iso27001 catalog")
		}
		if c.name == "" {
			t.Errorf("control %q has empty name", c.id)
		}
		if c.criteria == "" {
			t.Errorf("control %q has empty criteria", c.id)
		}
		if c.check == nil {
			t.Errorf("control %q has nil check function", c.id)
		}
		if seen[c.id] {
			t.Errorf("duplicate control id %q in iso27001 catalog", c.id)
		}
		seen[c.id] = true
	}
}

// TestValidFramework verifies the supported-framework predicate.
func TestValidFramework(t *testing.T) {
	cases := []struct {
		f  string
		ok bool
	}{
		{"soc2", true},
		{"iso27001", true},
		{"", false},
		{"SOC2", false},
		{"pci-dss", false},
	}
	for _, c := range cases {
		if got := ValidFramework(c.f); got != c.ok {
			t.Errorf("ValidFramework(%q) = %v, want %v", c.f, got, c.ok)
		}
	}
}

// TestTallyResults verifies the pass/fail/na counter.
func TestTallyResults(t *testing.T) {
	results := []ControlResult{
		{Status: ControlPass},
		{Status: ControlPass},
		{Status: ControlFail},
		{Status: ControlNA},
		{Status: ControlNA},
	}
	pass, fail, na := tallyResults(results)
	if pass != 2 {
		t.Errorf("pass = %d, want 2", pass)
	}
	if fail != 1 {
		t.Errorf("fail = %d, want 1", fail)
	}
	if na != 2 {
		t.Errorf("na = %d, want 2", na)
	}
}

// TestTallyResults_Empty verifies zero counts on an empty result set.
func TestTallyResults_Empty(t *testing.T) {
	pass, fail, na := tallyResults(nil)
	if pass != 0 || fail != 0 || na != 0 {
		t.Errorf("empty results should yield (0,0,0), got (%d,%d,%d)", pass, fail, na)
	}
}

// TestTotalControls verifies the TotalControls helper returns the right count
// for each framework and 0 for an unknown one.
func TestTotalControls(t *testing.T) {
	if n := TotalControls("soc2"); n != 13 {
		t.Errorf("TotalControls(soc2) = %d, want 13", n)
	}
	if n := TotalControls("iso27001"); n != 12 {
		t.Errorf("TotalControls(iso27001) = %d, want 12", n)
	}
	if n := TotalControls("unknown"); n != 0 {
		t.Errorf("TotalControls(unknown) = %d, want 0", n)
	}
}

// TestControlStatus_Values verifies the ControlStatus string constants are
// stable (the UI and DB depend on these exact strings).
func TestControlStatus_Values(t *testing.T) {
	if ControlPass != "pass" {
		t.Errorf("ControlPass = %q, want %q", ControlPass, "pass")
	}
	if ControlFail != "fail" {
		t.Errorf("ControlFail = %q, want %q", ControlFail, "fail")
	}
	if ControlNA != "na" {
		t.Errorf("ControlNA = %q, want %q", ControlNA, "na")
	}
}

// TestControlCatalog_ControlsByFrameworkComplete verifies both frameworks are
// registered in the lookup map.
func TestControlCatalog_ControlsByFrameworkComplete(t *testing.T) {
	for _, fw := range []string{"soc2", "iso27001"} {
		if _, ok := controlsByFramework[fw]; !ok {
			t.Errorf("controlsByFramework missing key %q", fw)
		}
	}
	if len(controlsByFramework) != 2 {
		t.Errorf("controlsByFramework has %d entries, want 2", len(controlsByFramework))
	}
}
