package ratelimits

import (
	"bytes"
	"encoding/json"
	"testing"
)

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

// TestLimitsShowTheirBounds checks that the limits report the defaults as the
// ceiling, the minimum rate and the built-in limits, and that a body read back
// from GET is accepted on PUT, its bounds ignored.
func TestLimitsShowTheirBounds(t *testing.T) {
	h := &Handler{
		Defaults: Defaults{OrganizationRate: 100, OrganizationCapacity: 500, UserRate: 30, UserCapacity: 100, APIKeyRate: 50, APIKeyCapacity: 200},
		BuiltIn:  []BuiltInLimit{{Name: "public", Per: "ip", Applies: "sign-in", Bucket: Bucket{Rate: 5, Capacity: 20}}},
	}
	rate, capacity := 10.0, 20
	v := h.view(OrganizationLimits{Organization: LimitConfig{Rate: &rate, Capacity: &capacity}})
	if v.Defaults.Organization != (Bucket{Rate: 100, Capacity: 500}) || v.Ceiling != v.Defaults || v.MinRate != MinRate || len(v.BuiltIn) != 1 {
		t.Errorf("view %+v; want the defaults as ceiling, the minimum rate and the built-in limit", v)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in limitsInput
	if err := dec.Decode(&in); err != nil || in.Organization.Rate == nil || *in.Organization.Rate != 10 {
		t.Errorf("a GET body sent back on PUT: %v, %+v; want it accepted with its override", err, in.OrganizationLimits)
	}
}
