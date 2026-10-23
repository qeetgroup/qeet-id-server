package gdpr

import (
	"testing"
)

// TestControlCatalog_SOC2 checks that the SOC 2 catalog has 13 well-formed
// controls.
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

// TestControlCatalog_ISO27001 checks that the ISO 27001 catalog has 12
// well-formed controls.
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

// TestTallyResults checks that tallyResults counts each status.
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

// TestTallyResults_Empty checks that no results give zero counts.
func TestTallyResults_Empty(t *testing.T) {
	pass, fail, na := tallyResults(nil)
	if pass != 0 || fail != 0 || na != 0 {
		t.Errorf("empty results should yield (0,0,0), got (%d,%d,%d)", pass, fail, na)
	}
}

// TestFrameworkCatalogs checks how many controls each framework has.
func TestFrameworkCatalogs(t *testing.T) {
	for framework, want := range map[string]int{"soc2": 13, "iso27001": 12} {
		if n := len(controlsByFramework[framework]); n != want {
			t.Errorf("%s has %d controls, want %d", framework, n, want)
		}
	}
}

// TestControlStatus_Values checks the ControlStatus strings, which the console
// and the database depend on.
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

// TestControlCatalog_ControlsByFrameworkComplete checks that exactly the two
// frameworks are registered.
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
