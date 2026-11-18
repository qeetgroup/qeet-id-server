package compliance

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/compliance/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ExternalAudit is an audit an external body carried out on the organization,
// or a certificate it issued, against a framework.
type ExternalAudit struct {
	ID        uuid.UUID  `json:"id"`
	Framework string     `json:"framework"`
	Kind      string     `json:"kind"`
	Body      string     `json:"body"`
	Scope     string     `json:"scope"`
	Reference string     `json:"reference"`
	IssuedOn  string     `json:"issued_on"`
	ExpiresOn *string    `json:"expires_on"`
	CreatedBy *uuid.UUID `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

// ExternalAuditInput is a new ExternalAudit; dates are YYYY-MM-DD.
type ExternalAuditInput struct {
	Framework string  `json:"framework"`
	Kind      string  `json:"kind"`
	Body      string  `json:"body"`
	Scope     string  `json:"scope"`
	Reference string  `json:"reference"`
	IssuedOn  string  `json:"issued_on"`
	ExpiresOn *string `json:"expires_on"`
}

// check trims in and names each field at fault.
func (in *ExternalAuditInput) check() (issued time.Time, expires *time.Time, err error) {
	in.Body, in.Scope, in.Reference = strings.TrimSpace(in.Body), strings.TrimSpace(in.Scope), strings.TrimSpace(in.Reference)
	var bad []errs.FieldError
	field := func(name, code, msg string) {
		bad = append(bad, errs.FieldError{Field: name, Code: code, Message: msg})
	}
	if in.Framework != "soc2" && in.Framework != "iso27001" {
		field("framework", "invalid", "Choose soc2 or iso27001.")
	}
	if in.Kind != "audit" && in.Kind != "certificate" {
		field("kind", "invalid", "Choose audit or certificate.")
	}
	if in.Body == "" || utf8.RuneCountInString(in.Body) > 200 {
		field("body", "invalid", "Name the auditor or certification body in up to 200 characters.")
	}
	if utf8.RuneCountInString(in.Scope) > 2000 {
		field("scope", "too_long", "Describe the scope in up to 2,000 characters.")
	}
	if utf8.RuneCountInString(in.Reference) > 200 {
		field("reference", "too_long", "Give the reference in up to 200 characters.")
	}
	on, perr := time.Parse(time.DateOnly, in.IssuedOn)
	if perr != nil {
		field("issued_on", "invalid", "Give the date as YYYY-MM-DD.")
	}
	issued = on
	if in.ExpiresOn != nil && *in.ExpiresOn != "" {
		until, eerr := time.Parse(time.DateOnly, *in.ExpiresOn)
		switch {
		case eerr != nil:
			field("expires_on", "invalid", "Give the date as YYYY-MM-DD.")
		case perr == nil && until.Before(on):
			field("expires_on", "before_issued", "The expiry can't be before the date issued.")
		}
		if eerr == nil {
			expires = &until
		}
	}
	if len(bad) > 0 {
		return issued, expires, errs.ErrValidationFailed.WithFields(bad)
	}
	return issued, expires, nil
}

// externalAudit maps a stored audit.
func externalAudit(id uuid.UUID, framework, kind, body, scope, reference string, issued time.Time, expires *time.Time, by *uuid.UUID, at time.Time) ExternalAudit {
	out := ExternalAudit{ID: id, Framework: framework, Kind: kind, Body: body, Scope: scope, Reference: reference,
		IssuedOn: issued.Format(time.DateOnly), CreatedBy: by, CreatedAt: at}
	if expires != nil {
		v := expires.Format(time.DateOnly)
		out.ExpiresOn = &v
	}
	return out
}

// Audits returns up to 200 of organizationID's external audits and certificates,
// latest first, of framework when not "".
func (s *EvidenceService) Audits(ctx context.Context, organizationID uuid.UUID, framework string) ([]ExternalAudit, error) {
	var f *string
	if framework != "" {
		f = &framework
	}
	rows, err := s.q.ListComplianceAudits(ctx, dbgen.ListComplianceAuditsParams{OrganizationID: organizationID, Framework: f})
	if err != nil {
		return nil, err
	}
	out := make([]ExternalAudit, len(rows))
	for i, r := range rows {
		out[i] = externalAudit(r.ID, r.Framework, r.Kind, r.Body, r.Scope, r.Reference, r.IssuedOn, r.ExpiresOn, r.CreatedBy, r.CreatedAt)
	}
	return out, nil
}

// RecordAudit stores an external audit or certificate of organizationID, as actor's.
func (s *EvidenceService) RecordAudit(ctx context.Context, organizationID uuid.UUID, in ExternalAuditInput, actor audit.Actor) (*ExternalAudit, error) {
	issued, expires, err := in.check()
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	r, err := s.q.WithTx(tx).InsertComplianceAudit(ctx, dbgen.InsertComplianceAuditParams{
		OrganizationID: organizationID, Framework: in.Framework, Kind: in.Kind, Body: in.Body, Scope: in.Scope, Reference: in.Reference,
		IssuedOn: issued, ExpiresOn: expires, CreatedBy: actor.UserID,
	})
	if err != nil {
		return nil, err
	}
	out := externalAudit(r.ID, r.Framework, r.Kind, r.Body, r.Scope, r.Reference, r.IssuedOn, r.ExpiresOn, r.CreatedBy, r.CreatedAt)
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.audit_recorded", "compliance_audit", out.ID,
		map[string]any{"framework": out.Framework, "kind": out.Kind, "body": out.Body, "issued_on": out.IssuedOn})); err != nil {
		return nil, err
	}
	return &out, tx.Commit(ctx)
}

// DeleteAudit removes one of organizationID's external audits, as actor's change.
func (s *EvidenceService) DeleteAudit(ctx context.Context, organizationID, id uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	r, err := s.q.WithTx(tx).DeleteComplianceAudit(ctx, dbgen.DeleteComplianceAuditParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.audit_deleted", "compliance_audit", id,
		map[string]any{"framework": r.Framework, "kind": r.Kind, "body": r.Body})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
