package billing

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
)

// Invoice tax. It is off until an operator configures the seller's jurisdiction
// (TaxConfig), so tax is never charged on a guess. Catalogue prices are net and
// tax is added on top, in integer minor units, before a checkout opens: the
// provider charges the total the invoice shows.

// TaxConfig holds the seller's tax settings. Tax applies only when Enabled is
// set and SellerCountry is not empty. An empty SellerState makes every Indian
// sale inter-state (IGST).
type TaxConfig struct {
	Enabled       bool   // charge tax; off by default
	SellerCountry string // ISO 3166-1 alpha-2 code of the seller's tax jurisdiction
	SellerState   string // seller's Indian state, for intra- versus inter-state GST
	GSTRateBps    int    // India GST rate in basis points; 0 means 1800 (18%)
}

// TaxInput is the tax input of one invoice, from the plan price and the billing
// profile.
type TaxInput struct {
	AmountMinor  int64  // net (tax-exclusive) taxable amount
	BuyerCountry string // billing profile country (ISO alpha-2)
	BuyerState   string // billing profile state/region
	TaxIDType    string // "none" | "gstin" | "vat"
}

// Tax type codes stored on the invoice.
const (
	TaxTypeNone         = "none"               // no tax
	TaxTypeGSTIntra     = "gst_cgst_sgst"      // intra-state India GST (CGST + SGST)
	TaxTypeGSTInter     = "gst_igst"           // inter-state India GST (IGST)
	TaxTypeGSTZeroRated = "gst_zero_rated"     // zero-rated India GST, such as exports
	TaxTypeVATReverse   = "vat_reverse_charge" // VAT paid by the buyer (reverse charge)
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

// taxFor computes the tax on a net amount for the tenant's billing profile,
// read through q. A profile that cannot be read is treated as empty, and one
// with no country takes country, the billing country the checkout was given.
func (s *Service) taxFor(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID, amountMinor int64, country string) TaxResult {
	in := TaxInput{AmountMinor: amountMinor, BuyerCountry: country}
	if p, err := billingProfile(ctx, q, tenantID); err == nil && p != nil {
		if p.Country != "" {
			in.BuyerCountry = p.Country
		}
		in.BuyerState = p.State
		in.TaxIDType = p.TaxIDType
	}
	return computeTax(s.tax, in)
}

// checkoutTax is the charge a checkout row recorded. A row whose parts don't
// add up to its total predates the tax columns, and charged no tax.
func checkoutTax(total, taxable, tax int64, rateBps int32, typ, place string) TaxResult {
	if taxable+tax != total {
		return noTax(total, place)
	}
	return TaxResult{TaxableMinor: taxable, TaxMinor: tax, TotalMinor: total, RateBps: int(rateBps), Type: typ, PlaceOfSupply: place}
}

// istZone is India Standard Time, in which a GST financial year is dated.
var istZone = time.FixedZone("IST", 5*60*60+30*60)

// financialYear names the Indian financial year, April to March, that t falls
// in, such as "2026-27".
func financialYear(t time.Time) string {
	t = t.In(istZone)
	y := t.Year()
	if t.Month() < time.April {
		y--
	}
	return fmt.Sprintf("%d-%02d", y, (y+1)%100)
}

// invoiceNumber is the n-th invoice number of financial year fy, such as
// 2026-27/000042: under GST's 16-character limit to n = 99,999,999.
func invoiceNumber(fy string, n int64) string {
	return fmt.Sprintf("%s/%06d", fy, n)
}

func noTax(amount int64, place string) TaxResult {
	return TaxResult{TaxableMinor: amount, TotalMinor: amount, RateBps: 0, Type: TaxTypeNone, PlaceOfSupply: place}
}

// computeTax applies the seller's tax rules to a net amount. It is pure.
func computeTax(cfg TaxConfig, in TaxInput) TaxResult {
	if !cfg.Enabled || strings.TrimSpace(cfg.SellerCountry) == "" {
		return noTax(in.AmountMinor, strings.ToUpper(strings.TrimSpace(in.BuyerCountry)))
	}
	seller := strings.ToUpper(strings.TrimSpace(cfg.SellerCountry))
	buyer := strings.ToUpper(strings.TrimSpace(in.BuyerCountry))

	// India GST.
	if seller == "IN" {
		// Domestic supply: a buyer in India, or of unknown country.
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

	// Non-India seller: EU B2B reverse charge when the buyer has a VAT ID.
	// Destination VAT rates are not modelled, so other sales are left untaxed
	// rather than guess a rate.
	if in.TaxIDType == "vat" {
		return TaxResult{
			TaxableMinor: in.AmountMinor, TaxMinor: 0, TotalMinor: in.AmountMinor,
			RateBps: 0, Type: TaxTypeVATReverse, PlaceOfSupply: buyer,
		}
	}
	return noTax(in.AmountMinor, buyer)
}
