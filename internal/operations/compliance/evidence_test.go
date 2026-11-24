package compliance

import (
	"testing"
)

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
