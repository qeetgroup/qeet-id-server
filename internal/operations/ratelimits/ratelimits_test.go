package ratelimits

import "testing"

// TestOverridesOnlyTighten checks that an override must stay within the
// platform's limit and above the minimum rate.
func TestOverridesOnlyTighten(t *testing.T) {
	limit := func(rate float64, capacity int) LimitConfig { return LimitConfig{Rate: &rate, Capacity: &capacity} }
	for _, c := range []struct {
		name string
		in   LimitConfig
		ok   bool
	}{
		{"unset", LimitConfig{}, true},
		{"the platform's own", limit(100, 500), true},
		{"tighter", limit(5, 10), true},
		{"the minimum", limit(MinRate, 1), true},
		{"a faster rate", limit(100.5, 500), false},
		{"a larger burst", limit(100, 501), false},
		{"below the minimum rate", limit(MinRate/2, 10), false},
		{"no burst", limit(5, 0), false},
		{"a negative rate", limit(-1, 10), false},
	} {
		if err := c.in.check("tenant", 100, 500); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
	}
}
