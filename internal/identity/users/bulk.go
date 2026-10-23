package user

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// maxImportBytes bounds a raw vendor-export upload (NDJSON/CSV/JSON).
const maxImportBytes = 10 * 1024 * 1024

// maxImportRows mirrors BulkCreateInput's own batch-size ceiling.
const maxImportRows = 1000

// Codes a BulkImportError carries besides the errs codes it reuses.
const (
	CodeImportFieldMissing = "user.import_field_missing"  // a required field is empty
	CodeImportFieldInvalid = "user.import_field_invalid"  // a field's value has the wrong format
	CodeImportFieldTooLong = "user.import_field_too_long" // a field's value is over its length limit
	CodeImportRowMalformed = "user.import_row_malformed"  // the export line, or with no line the file, can't be parsed
)

// importErrorCodes is every code a BulkImportError can carry.
var importErrorCodes = []string{
	CodeImportFieldMissing, CodeImportFieldInvalid, CodeImportFieldTooLong, CodeImportRowMalformed,
	errs.CodeUserImportSourceInvalid, errs.CodeAuthEmailExists,
	errs.CodeAuthPolicyPasswordTooShort, errs.CodeAuthPolicyPasswordNoUppercase,
	errs.CodeAuthPolicyPasswordNoNumber, errs.CodeAuthPolicyPasswordNoSymbol,
	errs.CodeAuthPolicyPasswordBreached, errs.CodeAuthPasswordWeak,
	errs.CodeInternal,
}

// userCreator creates one user (hashing + persistence). Injected into
// runBulkImport so the aggregation logic is unit-testable without a DB.
type userCreator func(ctx context.Context, in CreateInput) (*User, error)

// runBulkImport validates each row and creates it with create, carrying on past
// failed rows, and returns the per-row summary. create records each user's own
// audit and outbox evidence.
func runBulkImport(ctx context.Context, v *validator.Validate, tenantID uuid.UUID, rows []BulkUserInput, create userCreator) BulkImportResult {
	var res BulkImportResult
	for i, row := range rows {
		line := i + 1
		if row.line > 0 {
			line = row.line
		}
		if v != nil {
			if err := v.Struct(row); err != nil {
				res.Failed++
				code, field := validationIssue(err)
				res.Errors = append(res.Errors, BulkImportError{Line: line, Email: row.Email, Code: code, Field: field, Message: "invalid row: " + firstValidationMsg(err)})
				continue
			}
		}
		_, err := create(ctx, CreateInput{
			TenantID:    tenantID,
			Email:       row.Email,
			Password:    row.Password,
			DisplayName: row.DisplayName,
			Phone:       row.Phone,
		})
		if err != nil {
			res.Failed++
			// Any other failure stays generic: its cause can carry internal detail.
			rowErr := BulkImportError{Line: line, Email: row.Email, Code: errs.CodeInternal, Message: "could not create user"}
			// errs.*.WithDetail returns a copy (no Unwrap/Is), so match on the
			// stable code rather than identity.
			if e := errs.As(err); e != nil && e.Code == errs.ErrAuthEmailExists.Code {
				rowErr.Code, rowErr.Field, rowErr.Message = e.Code, "email", "a user with this email already exists"
			} else if e != nil && isPasswordRefusal(e.Code) {
				// Name the rule the row's password broke, so the operator can
				// fix that row and resubmit it alone.
				rowErr.Code, rowErr.Field, rowErr.Message = e.Code, "password", e.Message
			}
			res.Errors = append(res.Errors, rowErr)
			continue
		}
		res.Succeeded++
	}
	return res
}

// isPasswordRefusal reports whether code is a refusal from the password check
// (the organisation's rules, the offline baseline or the breach check).
func isPasswordRefusal(code string) bool {
	switch code {
	case errs.CodeAuthPolicyPasswordTooShort, errs.CodeAuthPolicyPasswordNoUppercase,
		errs.CodeAuthPolicyPasswordNoNumber, errs.CodeAuthPolicyPasswordNoSymbol,
		errs.CodeAuthPolicyPasswordBreached, errs.CodeAuthPasswordWeak:
		return true
	}
	return false
}

// firstValidationMsg renders a concise message from a validator error.
func firstValidationMsg(err error) string {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		return ve[0].Field() + " failed " + ve[0].Tag()
	}
	return "validation failed"
}

// validationIssue returns the code for the first rule err reports broken, and
// the JSON name of the BulkUserInput field that broke it.
func validationIssue(err error) (code, field string) {
	var ve validator.ValidationErrors
	if !errors.As(err, &ve) || len(ve) == 0 {
		return CodeImportFieldInvalid, ""
	}
	switch ve[0].Tag() {
	case "required":
		code = CodeImportFieldMissing
	case "max":
		code = CodeImportFieldTooLong
	default:
		code = CodeImportFieldInvalid
	}
	if f, ok := reflect.TypeFor[BulkUserInput]().FieldByName(ve[0].StructField()); ok {
		field, _, _ = strings.Cut(f.Tag.Get("json"), ",")
	}
	return code, field
}

// bulkCreate handles POST /v1/users/bulk. Each row is attempted on its own: a
// bad or duplicate row is reported in the response rather than failing the batch.
func (h *Handler) bulkCreate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in BulkCreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Never let a caller import into a tenant other than their own.
	if in.TenantID != uuid.Nil && in.TenantID != tenantID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("cannot import users into another tenant"))
		return
	}
	// Envelope validation (batch size); per-row validation happens inside
	// runBulkImport so one bad row doesn't reject the whole batch.
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}

	// Each row's password is checked against the tenant's rules before its
	// user is written; a refused row is reported and the batch carries on.
	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		var hash string
		if ci.Password != "" {
			ph, herr := h.hashNewPassword(ctx, tenantID, ci.Email, ci.Password)
			if herr != nil {
				return nil, herr
			}
			hash = ph
		}
		return h.createWithEvidence(r, ci, hash)
	}

	res := runBulkImport(r.Context(), h.Validate, tenantID, in.Users, create)
	if err := h.auditBulkImport(r, tenantID, res); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// bulkImportFromVendor handles POST /v1/users/bulk/import?source=auth0|cognito|azure_b2c.
// The body is the vendor's own export file, parsed by ParseVendorExport and
// imported like bulkCreate. Vendors don't export password hashes, so imported
// users have no password.
func (h *Handler) bulkImportFromVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	source, ok := ParseImportSource(r.URL.Query().Get("source"))
	if !ok {
		httpx.WriteError(w, r, errs.ErrUserImportSourceInvalid.WithDetail(importSourceHint()))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxImportBytes+1))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("could not read request body"))
		return
	}
	if len(raw) > maxImportBytes {
		httpx.WriteError(w, r, errs.ErrUserImportFileTooLarge)
		return
	}

	rows, parseErrs := ParseVendorExport(source, raw)
	if len(rows) == 0 && len(parseErrs) == 0 {
		httpx.WriteError(w, r, errs.ErrUserImportEmpty)
		return
	}
	if len(rows) > maxImportRows {
		httpx.WriteError(w, r, errs.ErrUserImportBatchTooLarge)
		return
	}

	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		return h.createWithEvidence(r, ci, "")
	}
	res := runBulkImport(r.Context(), h.Validate, tenantID, rows, create)
	// Parse-level failures (rows that never reached validation) count toward
	// the same summary, with their own line numbers from the source file.
	res.Failed += len(parseErrs)
	res.Errors = append(parseErrs, res.Errors...)

	if err := h.auditBulkImport(r, tenantID, res); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// auditBulkImport records a single summary row for the batch.
func (h *Handler) auditBulkImport(r *http.Request, tenantID uuid.UUID, res BulkImportResult) error {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actorID *uuid.UUID
	actorType := "system"
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
		if p.ActorType != "" {
			actorType = p.ActorType
		}
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "user.bulk_imported",
		ResourceType: "tenant",
		ResourceID:   &tenantID,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"succeeded": res.Succeeded, "failed": res.Failed},
	}); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: tenantID,
		Topic:       "user.events",
		EventType:   "user.bulk_imported",
		Payload: map[string]any{
			"tenant_id": tenantID,
			"succeeded": res.Succeeded,
			"failed":    res.Failed,
		},
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
