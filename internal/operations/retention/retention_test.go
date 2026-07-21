package retention

import "testing"

func TestClampDays(t *testing.T) {
	cases := map[int]int{0: 1, -5: 1, 1: 1, 30: 30, 3650: 3650, 9999: 3650}
	for in, want := range cases {
		if got := clampDays(in); got != want {
			t.Errorf("clampDays(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestDefaultPolicyIsOptIn(t *testing.T) {
	d := DefaultPolicy()
	if d.DeletedUsersEnabled {
		t.Error("retention must be opt-in (disabled by default)")
	}
	if d.DeletedUsersDays != 30 {
		t.Errorf("default window = %d, want 30", d.DeletedUsersDays)
	}
}
