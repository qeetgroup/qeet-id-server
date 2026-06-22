package billing

import (
	"testing"
	"time"
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
