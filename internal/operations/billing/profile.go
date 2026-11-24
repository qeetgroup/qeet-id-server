package billing

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/billing/dbgen"
)

var gstinRe = regexp.MustCompile(`^[0-9A-Z]{15}$`)

// GetBillingProfile returns the organization's billing and tax details, or an empty
// profile with tax_id_type "none" if none has been saved.
func (s *Service) GetBillingProfile(ctx context.Context, organizationID uuid.UUID) (*BillingProfile, error) {
	return billingProfile(ctx, s.q, organizationID)
}

// billingProfile is GetBillingProfile read through q.
func billingProfile(ctx context.Context, q *dbgen.Queries, organizationID uuid.UUID) (*BillingProfile, error) {
	row, err := q.GetBillingProfile(ctx, organizationID)
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

// UpsertBillingProfile validates and saves the organization's billing and tax details.
func (s *Service) UpsertBillingProfile(ctx context.Context, organizationID uuid.UUID, p BillingProfile) error {
	if p.TaxIDType == "" {
		p.TaxIDType = "none"
	}
	switch p.TaxIDType {
	case "none":
		p.TaxID = ""
	case "gstin":
		if !gstinRe.MatchString(strings.ToUpper(strings.TrimSpace(p.TaxID))) {
			return ErrTaxIDInvalid.WithMessage("Enter a valid 15-character GSTIN.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	case "vat":
		if strings.TrimSpace(p.TaxID) == "" {
			return ErrTaxIDInvalid.WithMessage("Enter your VAT number.")
		}
		p.TaxID = strings.ToUpper(strings.TrimSpace(p.TaxID))
	default:
		return ErrTaxIDInvalid.WithMessage("Unsupported tax ID type.")
	}
	return s.q.UpsertBillingProfile(ctx, dbgen.UpsertBillingProfileParams{
		OrganizationID: organizationID,
		LegalName:      strings.TrimSpace(p.LegalName),
		BillingEmail:   strings.TrimSpace(p.BillingEmail),
		AddressLine1:   strings.TrimSpace(p.AddressLine1),
		AddressLine2:   strings.TrimSpace(p.AddressLine2),
		City:           strings.TrimSpace(p.City),
		State:          strings.TrimSpace(p.State),
		PostalCode:     strings.TrimSpace(p.PostalCode),
		Country:        strings.ToUpper(strings.TrimSpace(p.Country)),
		TaxIDType:      p.TaxIDType,
		TaxID:          p.TaxID,
	})
}
