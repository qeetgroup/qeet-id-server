package analytics

import (
	"encoding/json"
	"math"
	"testing"
)

func TestPctChange(t *testing.T) {
	cases := []struct {
		name      string
		now, prev int64
		expected  float64
	}{
		{"both zero → no change", 0, 0, 0},
		{"zero→nonzero is +100%", 0, 100, -100},
		{"nonzero→zero is +100% (not /0)", 100, 0, 100},
		{"50→100 = +100%", 100, 50, 100},
		{"100→50 = -50%", 50, 100, -50},
		{"no change", 42, 42, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pctChange(c.now, c.prev)
			if math.Abs(got-c.expected) > 0.001 {
				t.Fatalf("pctChange(%d, %d) = %v, want %v", c.now, c.prev, got, c.expected)
			}
		})
	}
}

// Lock in the JSON envelope shape so frontend type drift surfaces here
// rather than as a runtime "undefined.toLocaleString()" in the dashboard.
func TestOverview_JSONShape(t *testing.T) {
	o := Overview{}
	o.KPIs.MAU = Metric{Value: 100, DeltaPct: 5.5}
	o.UserTrend14d = []TrendPoint{{Date: "2026-05-26", Value: 42}}
	o.LoginActivity14d = []ActivityPoint{{Date: "2026-05-26", Password: 1, Passkey: 2}}
	o.LoginMethodsMix = []MethodSlice{{Method: "password", Value: 100}}
	o.MFAMethodsAdoption = []MethodCount{{Method: "TOTP", Users: 7}}
	o.FailedLoginsHourly24h = []HourlyPoint{{Hour: "12:00", Attempts: 3}}

	b, err := json.Marshal(o)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []string{
		`"kpis"`, `"mau"`, `"value":100`, `"delta_pct":5.5`,
		`"user_trend_14d"`, `"login_activity_14d"`,
		`"login_methods_mix"`, `"mfa_methods_adoption"`,
		`"failed_logins_hourly_24h"`,
		`"date":"2026-05-26"`, `"hour":"12:00"`,
	}
	got := string(b)
	for _, fragment := range want {
		if !contains(got, fragment) {
			t.Errorf("JSON missing %q\n--- got ---\n%s", fragment, got)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
