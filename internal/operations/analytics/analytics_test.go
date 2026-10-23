package analytics

import (
	"encoding/json"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// TestOverview_JSONShape checks the JSON shape of Overview, so drift from the
// console's types fails here rather than in the dashboard.
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
		`"user_trend_14d"`, `"login_activity_14d"`, `"magic_link":0`, `"ldap":0`,
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

// TestCountedActionsAreRecorded checks that every audit action the dashboard
// counts is one that some non-test code in internal/ records, so a renamed
// action can't leave a chart at zero.
func TestCountedActionsAreRecorded(t *testing.T) {
	counted := map[string]bool{}
	actionRe := regexp.MustCompile(`action = '([a-z_.]+)'`)
	for _, name := range []string{"queries.sql", "analytics.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range actionRe.FindAllStringSubmatch(string(src), -1) {
			counted[m[1]] = true
		}
	}
	if len(counted) == 0 {
		t.Fatal("found no counted actions; the pattern is probably broken")
	}

	recorded := map[string]bool{}
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "dbgen" || d.Name() == "analytics" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for action := range counted {
			if strings.Contains(string(src), `"`+action+`"`) {
				recorded[action] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for action := range counted {
		if !recorded[action] {
			t.Errorf("the dashboard counts %q, which nothing in internal/ records", action)
		}
	}
}
