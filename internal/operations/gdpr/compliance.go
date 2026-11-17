package gdpr

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// knownControl reports whether id is a control of a framework's catalog.
func knownControl(id string) bool {
	for _, catalog := range controlsByFramework {
		for _, c := range catalog {
			if c.id == id {
				return true
			}
		}
	}
	return false
}

// Owners returns who answers for each of organizationID's controls that has an
// owner.
func (s *EvidenceService) Owners(ctx context.Context, organizationID uuid.UUID) ([]ControlOwner, error) {
	rows, err := s.q.ListControlOwners(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]ControlOwner, len(rows))
	for i, r := range rows {
		out[i] = ControlOwner{ControlID: r.ControlID, UserID: r.UserID, Email: r.Email, DisplayName: r.DisplayName, UpdatedAt: r.UpdatedAt}
	}
	return out, nil
}

// SetOwner makes userID, one of organizationID's people, answer for controlID, as
// actor's change.
func (s *EvidenceService) SetOwner(ctx context.Context, organizationID uuid.UUID, controlID string, userID uuid.UUID, actor audit.Actor) error {
	if !knownControl(controlID) {
		return errs.ErrNotFound
	}
	member, err := s.q.IsOrganizationMember(ctx, dbgen.IsOrganizationMemberParams{UserID: userID, OrganizationID: pgtype.UUID{Bytes: organizationID, Valid: true}})
	if err != nil {
		return err
	}
	if !member {
		return errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "user_id", Code: "not_a_member", Message: "Choose one of the organisation's people.",
		}})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := s.q.WithTx(tx).UpsertControlOwner(ctx, dbgen.UpsertControlOwnerParams{
		OrganizationID: organizationID, ControlID: controlID, UserID: userID, UpdatedBy: pgUUIDNullable(actor.UserID),
	}); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.control_owner_set", "user", userID,
		map[string]any{"control_id": controlID, "user_id": userID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RemoveOwner leaves controlID without an owner, as actor's change.
func (s *EvidenceService) RemoveOwner(ctx context.Context, organizationID uuid.UUID, controlID string, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteControlOwner(ctx, dbgen.DeleteControlOwnerParams{OrganizationID: organizationID, ControlID: controlID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "compliance.control_owner_removed", "compliance_control", uuid.Nil,
		map[string]any{"control_id": controlID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

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
func (in *ExternalAuditInput) check() (issued, expires pgtype.Date, err error) {
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
	issued = pgtype.Date{Time: on, Valid: perr == nil}
	if in.ExpiresOn != nil && *in.ExpiresOn != "" {
		until, eerr := time.Parse(time.DateOnly, *in.ExpiresOn)
		switch {
		case eerr != nil:
			field("expires_on", "invalid", "Give the date as YYYY-MM-DD.")
		case perr == nil && until.Before(on):
			field("expires_on", "before_issued", "The expiry can't be before the date issued.")
		}
		expires = pgtype.Date{Time: until, Valid: eerr == nil}
	}
	if len(bad) > 0 {
		return issued, expires, errs.ErrValidationFailed.WithFields(bad)
	}
	return issued, expires, nil
}

// externalAudit maps a stored audit.
func externalAudit(id uuid.UUID, framework, kind, body, scope, reference string, issued, expires pgtype.Date, by pgtype.UUID, at time.Time) ExternalAudit {
	out := ExternalAudit{ID: id, Framework: framework, Kind: kind, Body: body, Scope: scope, Reference: reference,
		IssuedOn: issued.Time.Format(time.DateOnly), CreatedBy: toUUIDPtr(by), CreatedAt: at}
	if expires.Valid {
		v := expires.Time.Format(time.DateOnly)
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
		IssuedOn: issued, ExpiresOn: expires, CreatedBy: pgUUIDNullable(actor.UserID),
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

func (h *Handler) listOwners(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.Owners(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) setOwner(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Evidence.SetOwner(r.Context(), tid, chi.URLParam(r, "controlID"), in.UserID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) removeOwner(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Evidence.RemoveOwner(r.Context(), tid, chi.URLParam(r, "controlID"), audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listAudits(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.Audits(r.Context(), tid, r.URL.Query().Get("framework"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) recordAudit(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ExternalAuditInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Evidence.RecordAudit(r.Context(), tid, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handler) deleteAudit(w http.ResponseWriter, r *http.Request) {
	tid, err := requireEvidencePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrGDPRIDInvalid)
		return
	}
	if err := h.Evidence.DeleteAudit(r.Context(), tid, id, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
