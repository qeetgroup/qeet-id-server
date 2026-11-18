package billing

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
)

func TestNormalizeCurrency(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"usd", "USD", true},
		{"USD", "USD", true},
		{"  eur ", "EUR", true},
		{"jpy", "JPY", true},
		{"US", "US", false},
		{"usdx", "USDX", false},
		{"12a", "12A", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeCurrency(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("normalizeCurrency(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSubscriptionGrants(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Hour), now.Add(time.Hour)
	cases := []struct {
		name string
		sub  Subscription
		want bool
	}{
		{"active within its period", Subscription{Status: "active", CurrentPeriodEnd: &after}, true},
		{"active past its period", Subscription{Status: "active", CurrentPeriodEnd: &before}, false},
		{"cancel at period end, within it", Subscription{Status: "active", CancelAtPeriodEnd: true, CurrentPeriodEnd: &after}, true},
		{"cancel at period end, past it", Subscription{Status: "active", CancelAtPeriodEnd: true, CurrentPeriodEnd: &before}, false},
		{"past due within its period", Subscription{Status: "past_due", CurrentPeriodEnd: &after}, true},
		{"past due past its period", Subscription{Status: "past_due", CurrentPeriodEnd: &before}, false},
		{"trial running", Subscription{Status: "trialing", TrialEnd: &after, CurrentPeriodEnd: &after}, true},
		{"trial ended", Subscription{Status: "trialing", TrialEnd: &before, CurrentPeriodEnd: &before}, false},
		{"canceled", Subscription{Status: "canceled", CurrentPeriodEnd: &after}, false},
		{"active with no period", Subscription{Status: "active"}, false},
		{"none", Subscription{Status: "none"}, false},
	}
	for _, c := range cases {
		if got := c.sub.Grants(now); got != c.want {
			t.Errorf("%s: Grants = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPeriodEnd(t *testing.T) {
	start := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	if got := periodEnd(start, "month"); !got.Equal(start.AddDate(0, 1, 0)) {
		t.Errorf("month end = %v", got)
	}
	if got := periodEnd(start, "year"); !got.Equal(start.AddDate(1, 0, 0)) {
		t.Errorf("year end = %v", got)
	}
	// Unknown interval defaults to monthly.
	if got := periodEnd(start, "weird"); !got.Equal(start.AddDate(0, 1, 0)) {
		t.Errorf("default end = %v", got)
	}
}

func TestBuiltinPlansArePricedConsistently(t *testing.T) {
	// Every builtin plan must price every currency the others do, so an organization
	// can pick any seeded currency on any plan.
	var currencies map[string]bool
	for _, b := range builtins {
		cur := map[string]bool{}
		for c := range b.prices {
			cur[c] = true
		}
		if currencies == nil {
			currencies = cur
			continue
		}
		for c := range currencies {
			if !cur[c] {
				t.Errorf("plan %q missing price for %q", b.code, c)
			}
		}
	}
}

func TestCostsNoMore(t *testing.T) {
	starter := planPrice{code: "starter", interval: "month", currency: "USD", amountMinor: 2900}
	active := func(interval, currency string, amount int64) dbgen.GetSubscriptionRow {
		return dbgen.GetSubscriptionRow{Status: "active", Interval: interval, Currency: currency, AmountMinor: amount,
			CurrentPeriodEnd: time.Now().Add(24 * time.Hour)}
	}
	lapsed := active("month", "USD", 9900)
	lapsed.CurrentPeriodEnd = time.Now().Add(-time.Hour)
	cases := []struct {
		name    string
		current dbgen.GetSubscriptionRow
		want    bool
	}{
		{"a dearer current plan", active("month", "USD", 9900), true},
		{"the same price", active("month", "USD", 2900), true},
		{"a cheaper current plan", active("month", "USD", 0), false},
		{"another currency", active("month", "INR", 800000), false},
		{"another interval", active("year", "USD", 99000), false},
		{"a trial", dbgen.GetSubscriptionRow{Status: "trialing", Interval: "month", Currency: "USD", AmountMinor: 9900}, false},
		{"a past-due plan", dbgen.GetSubscriptionRow{Status: "past_due", Interval: "month", Currency: "USD", AmountMinor: 9900}, false},
		{"a dearer plan whose period ended", lapsed, false},
	}
	for _, c := range cases {
		if got := costsNoMore(starter, c.current); got != c.want {
			t.Errorf("costsNoMore(starter, %s) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestBuiltinPlansPromiseOnlyWhatShips keeps the catalogue the console and the
// website show to what the product actually does. Each phrase below names
// something that isn't built or committed to: an uptime figure or SLA, keys
// the customer brings, data residency, a dedicated organization, a certification,
// a custom sign-in domain, or usage metering.
func TestBuiltinPlansPromiseOnlyWhatShips(t *testing.T) {
	unsupported := []string{"uptime", "SLA", "BYOK", "residency", "Dedicated organization", "HIPAA", "& domain", "metered"}
	for _, p := range builtins {
		for _, line := range p.features {
			for _, phrase := range unsupported {
				if strings.Contains(line, phrase) {
					t.Errorf("plan %s promises %q in %q", p.code, phrase, line)
				}
			}
		}
	}
}

// TestYearlyPlansMatchMonthlyFeatures holds the yearly plans to the features of
// the monthly plan they bill for, so a change to one can't miss the other.
func TestYearlyPlansMatchMonthlyFeatures(t *testing.T) {
	byCode := map[string]builtinPlan{}
	for _, p := range builtins {
		byCode[p.code] = p
	}
	for _, p := range builtins {
		if p.interval != "year" {
			continue
		}
		monthly, ok := byCode[strings.TrimSuffix(p.code, "_year")]
		if !ok {
			t.Errorf("yearly plan %s has no monthly plan", p.code)
			continue
		}
		if !slices.Equal(p.features, monthly.features) {
			t.Errorf("plan %s features differ from %s", p.code, monthly.code)
		}
	}
}
