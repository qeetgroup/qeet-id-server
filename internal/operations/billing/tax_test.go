package billing

import "testing"

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
