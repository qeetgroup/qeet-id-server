package billing

import (
	"testing"
	"time"
)

func TestComputeTax(t *testing.T) {
	inIN := TaxConfig{Enabled: true, SellerCountry: "IN", SellerState: "Karnataka", GSTRateBps: 1800}

	cases := []struct {
		name string
		cfg  TaxConfig
		in   TaxInput
		want TaxResult
	}{
		{
			name: "disabled → no tax",
			cfg:  TaxConfig{Enabled: false, SellerCountry: "IN", SellerState: "Karnataka"},
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN", BuyerState: "Karnataka"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 0, TotalMinor: 10000, RateBps: 0, Type: TaxTypeNone, PlaceOfSupply: "IN"},
		},
		{
			name: "seller country unset → no tax even if enabled",
			cfg:  TaxConfig{Enabled: true, SellerCountry: "", GSTRateBps: 1800},
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN"},
			want: TaxResult{TaxableMinor: 10000, TotalMinor: 10000, Type: TaxTypeNone, PlaceOfSupply: "IN"},
		},
		{
			name: "India intra-state → CGST+SGST 18%",
			cfg:  inIN,
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN", BuyerState: "karnataka"}, // case-insensitive
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 1800, TotalMinor: 11800, RateBps: 1800, Type: TaxTypeGSTIntra, PlaceOfSupply: "karnataka"},
		},
		{
			name: "India inter-state → IGST 18%",
			cfg:  inIN,
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN", BuyerState: "Maharashtra"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 1800, TotalMinor: 11800, RateBps: 1800, Type: TaxTypeGSTInter, PlaceOfSupply: "Maharashtra"},
		},
		{
			name: "India, unknown buyer state → inter-state (IGST), place IN",
			cfg:  inIN,
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 1800, TotalMinor: 11800, RateBps: 1800, Type: TaxTypeGSTInter, PlaceOfSupply: "IN"},
		},
		{
			name: "India seller, buyer abroad → export zero-rated",
			cfg:  inIN,
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "US"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 0, TotalMinor: 10000, RateBps: 0, Type: TaxTypeGSTZeroRated, PlaceOfSupply: "US"},
		},
		{
			name: "EU seller, buyer has VAT id → reverse charge 0%",
			cfg:  TaxConfig{Enabled: true, SellerCountry: "IE", GSTRateBps: 0},
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "DE", TaxIDType: "vat"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 0, TotalMinor: 10000, RateBps: 0, Type: TaxTypeVATReverse, PlaceOfSupply: "DE"},
		},
		{
			name: "EU seller, no VAT id → untaxed (rate table not modelled)",
			cfg:  TaxConfig{Enabled: true, SellerCountry: "IE"},
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "DE", TaxIDType: "none"},
			want: TaxResult{TaxableMinor: 10000, TotalMinor: 10000, Type: TaxTypeNone, PlaceOfSupply: "DE"},
		},
		{
			name: "India default rate when GSTRateBps unset",
			cfg:  TaxConfig{Enabled: true, SellerCountry: "IN", SellerState: "Karnataka"},
			in:   TaxInput{AmountMinor: 10000, BuyerCountry: "IN", BuyerState: "Karnataka"},
			want: TaxResult{TaxableMinor: 10000, TaxMinor: 1800, TotalMinor: 11800, RateBps: 1800, Type: TaxTypeGSTIntra, PlaceOfSupply: "Karnataka"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := computeTax(c.cfg, c.in)
			if got != c.want {
				t.Errorf("computeTax()\n got  %+v\n want %+v", got, c.want)
			}
		})
	}
}

func TestFinancialYear(t *testing.T) {
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Date(2026, 4, 1, 0, 0, 0, 0, istZone), "2026-27"},
		{time.Date(2027, 3, 31, 23, 59, 0, 0, istZone), "2026-27"},
		// 31 March, 19:00 UTC is already 1 April in India.
		{time.Date(2027, 3, 31, 19, 0, 0, 0, time.UTC), "2027-28"},
		{time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC), "2025-26"},
		{time.Date(2099, 12, 1, 0, 0, 0, 0, time.UTC), "2099-00"},
	}
	for _, c := range cases {
		if got := financialYear(c.at); got != c.want {
			t.Errorf("financialYear(%v) = %q, want %q", c.at, got, c.want)
		}
	}
	if got := invoiceNumber("2026-27", 42); got != "2026-27/000042" {
		t.Errorf("invoiceNumber = %q", got)
	}
	if n := invoiceNumber("2026-27", 99_999_999); len(n) > 16 {
		t.Errorf("invoice number %q is longer than GST's 16 characters", n)
	}
}

func TestCheckoutTax(t *testing.T) {
	got := checkoutTax(11800, 10000, 1800, 1800, TaxTypeGSTInter, "Maharashtra")
	want := TaxResult{TaxableMinor: 10000, TaxMinor: 1800, TotalMinor: 11800, RateBps: 1800, Type: TaxTypeGSTInter, PlaceOfSupply: "Maharashtra"}
	if got != want {
		t.Errorf("checkoutTax() = %+v, want %+v", got, want)
	}
	// A row from before the tax columns has no breakdown: its total was untaxed.
	got = checkoutTax(9900, 0, 0, 0, TaxTypeNone, "")
	if want := noTax(9900, ""); got != want {
		t.Errorf("checkoutTax() of a legacy row = %+v, want %+v", got, want)
	}
}
