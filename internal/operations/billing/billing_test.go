package billing

import (
	"testing"
	"time"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
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
	// Every builtin plan must price every currency the others do, so a tenant
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
		return dbgen.GetSubscriptionRow{Status: "active", Interval: interval, Currency: currency, AmountMinor: amount}
	}
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
	}
	for _, c := range cases {
		if got := costsNoMore(starter, c.current); got != c.want {
			t.Errorf("costsNoMore(starter, %s) = %v, want %v", c.name, got, c.want)
		}
	}
}
