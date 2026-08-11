package billing

import (
	"context"
	"strings"

	"github.com/google/uuid"
)

// Tax computation for invoices. This is deliberately config-gated and OFF by
// default: until an operator sets their registered jurisdiction (TaxConfig),
// computeTax returns zero tax, so no tax is ever charged on a guess. Rates and
// place-of-supply rules are money-sensitive — keep this pure + tested and adjust
// the config, not hardcoded assumptions.
//
// Model: catalog prices are treated as NET (tax-exclusive); tax is added on top.
// Amounts are integer minor units.

// TaxConfig holds seller-side tax settings (wired from config at bootstrap).
type TaxConfig struct {
	Enabled bool
	// SellerCountry is the ISO-3166 alpha-2 code of the seller's tax jurisdiction
	// (e.g. "IN"). Empty disables tax regardless of Enabled.
	SellerCountry string
	// SellerState is the seller's state (India only) — used to decide intra-state
	// (CGST+SGST) vs inter-state (IGST). Empty ⇒ always treated as inter-state (IGST).
	SellerState string
	// GSTRateBps is the India GST rate in basis points (1800 = 18%). Defaults to 1800.
	GSTRateBps int
}

// TaxInput is the per-invoice input derived from the plan price + billing profile.
type TaxInput struct {
	AmountMinor  int64  // net (tax-exclusive) taxable amount
	BuyerCountry string // billing profile country (ISO alpha-2)
	BuyerState   string // billing profile state/region
	TaxIDType    string // "none" | "gstin" | "vat"
}

// Tax type codes stored on the invoice.
const (
	TaxTypeNone         = "none"
	TaxTypeGSTIntra     = "gst_cgst_sgst" // intra-state India GST (CGST + SGST)
	TaxTypeGSTInter     = "gst_igst"      // inter-state India GST (IGST)
	TaxTypeGSTZeroRated = "gst_zero_rated"
	TaxTypeVATReverse   = "vat_reverse_charge"
)

// TaxResult is the computed breakdown recorded on the invoice.
type TaxResult struct {
	TaxableMinor  int64
	TaxMinor      int64
	TotalMinor    int64
	RateBps       int
	Type          string
	PlaceOfSupply string
}

// taxFor resolves the tenant's billing profile and computes the tax on a net
// amount. A missing/unreadable profile falls back to a bare input (still safe:
// disabled config ⇒ zero tax).
func (s *Service) taxFor(ctx context.Context, tenantID uuid.UUID, amountMinor int64) TaxResult {
	in := TaxInput{AmountMinor: amountMinor}
	if p, err := s.GetBillingProfile(ctx, tenantID); err == nil && p != nil {
		in.BuyerCountry = p.Country
		in.BuyerState = p.State
		in.TaxIDType = p.TaxIDType
	}
	return computeTax(s.tax, in)
}

func noTax(amount int64, place string) TaxResult {
	return TaxResult{TaxableMinor: amount, TotalMinor: amount, RateBps: 0, Type: TaxTypeNone, PlaceOfSupply: place}
}

// computeTax applies the seller's tax rules to a net amount. Pure + deterministic.
func computeTax(cfg TaxConfig, in TaxInput) TaxResult {
	if !cfg.Enabled || strings.TrimSpace(cfg.SellerCountry) == "" {
		return noTax(in.AmountMinor, strings.ToUpper(strings.TrimSpace(in.BuyerCountry)))
	}
	seller := strings.ToUpper(strings.TrimSpace(cfg.SellerCountry))
	buyer := strings.ToUpper(strings.TrimSpace(in.BuyerCountry))

	// India GST.
	if seller == "IN" {
		// Domestic supply (buyer in India, or unknown → assume domestic to be safe).
		if buyer == "" || buyer == "IN" {
			rate := cfg.GSTRateBps
			if rate <= 0 {
				rate = 1800
			}
			tax := in.AmountMinor * int64(rate) / 10_000
			sameState := cfg.SellerState != "" &&
				strings.EqualFold(strings.TrimSpace(in.BuyerState), strings.TrimSpace(cfg.SellerState))
			typ := TaxTypeGSTInter
			if sameState {
				typ = TaxTypeGSTIntra
			}
			place := strings.TrimSpace(in.BuyerState)
			if place == "" {
				place = "IN"
			}
			return TaxResult{
				TaxableMinor: in.AmountMinor, TaxMinor: tax, TotalMinor: in.AmountMinor + tax,
				RateBps: rate, Type: typ, PlaceOfSupply: place,
			}
		}
		// Buyer outside India → export of services, zero-rated.
		return TaxResult{
			TaxableMinor: in.AmountMinor, TaxMinor: 0, TotalMinor: in.AmountMinor,
			RateBps: 0, Type: TaxTypeGSTZeroRated, PlaceOfSupply: buyer,
		}
	}

	// Non-India seller: EU B2B reverse charge when the buyer supplies a VAT ID.
	// Destination-country VAT *rates* are not modelled yet (needs a validated
	// rate table) — until then, non-reverse-charge cases are left untaxed rather
	// than guessing a rate.
	if in.TaxIDType == "vat" {
		return TaxResult{
			TaxableMinor: in.AmountMinor, TaxMinor: 0, TotalMinor: in.AmountMinor,
			RateBps: 0, Type: TaxTypeVATReverse, PlaceOfSupply: buyer,
		}
	}
	return noTax(in.AmountMinor, buyer)
}
