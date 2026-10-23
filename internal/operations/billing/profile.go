package billing

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

var gstinRe = regexp.MustCompile(`^[0-9A-Z]{15}$`)

// GetBillingProfile returns the tenant's billing and tax details, or an empty
// profile with tax_id_type "none" if none has been saved.
func (s *Service) GetBillingProfile(ctx context.Context, tenantID uuid.UUID) (*BillingProfile, error) {
	return billingProfile(ctx, s.q, tenantID)
}

// billingProfile is GetBillingProfile read through q.
func billingProfile(ctx context.Context, q *dbgen.Queries, tenantID uuid.UUID) (*BillingProfile, error) {
	row, err := q.GetBillingProfile(ctx, tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return &BillingProfile{TaxIDType: "none"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &BillingProfile{
		LegalName:    row.LegalName,
		BillingEmail: row.BillingEmail,
		AddressLine1: row.AddressLine1,
		AddressLine2: row.AddressLine2,
		City:         row.City,
		State:        row.State,
		PostalCode:   row.PostalCode,
		Country:      row.Country,
		TaxIDType:    row.TaxIDType,
		TaxID:        row.TaxID,
	}, nil
}

// UpsertBillingProfile validates and saves the tenant's billing and tax details.
func (s *Service) UpsertBillingProfile(ctx context.Context, tenantID uuid.UUID, p BillingProfile) error {
	if p.TaxIDType == "" {
		p.TaxIDType = "none"
	}
	switch p.TaxIDType {
	case "none":
		p.TaxID = ""
	case "gstin":
		if !gstinRe.MatchString(strings.ToUpper(strings.TrimSpace(p.TaxID))) {
			return errs.ErrBillingTaxIDInvalid.WithMessage("Enter a valid 15-character GSTIN.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	case "vat":
		if strings.TrimSpace(p.TaxID) == "" {
			return errs.ErrBillingTaxIDInvalid.WithMessage("Enter your VAT number.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	default:
		return errs.ErrBillingTaxIDInvalid.WithMessage("Unsupported tax ID type.")
	}
	return s.q.UpsertBillingProfile(ctx, dbgen.UpsertBillingProfileParams{
		TenantID:     tenantID,
		LegalName:    strings.TrimSpace(p.LegalName),
		BillingEmail: strings.TrimSpace(p.BillingEmail),
		AddressLine1: strings.TrimSpace(p.AddressLine1),
		AddressLine2: strings.TrimSpace(p.AddressLine2),
		City:         strings.TrimSpace(p.City),
		State:        strings.TrimSpace(p.State),
		PostalCode:   strings.TrimSpace(p.PostalCode),
		Country:      strings.ToUpper(strings.TrimSpace(p.Country)),
		TaxIDType:    p.TaxIDType,
		TaxID:        p.TaxID,
	})
}
