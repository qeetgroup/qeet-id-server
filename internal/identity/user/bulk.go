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

	"github.com/qeetgroup/qeet-id-server/internal/identity/user/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
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
	CodeImportSourceInvalid, errs.CodeAuthEmailExists, errs.CodeUserDomainManaged,
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
func runBulkImport(ctx context.Context, v *validator.Validate, organizationID uuid.UUID, rows []BulkUserInput, create userCreator) BulkImportResult {
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
		u, err := create(ctx, CreateInput{
			OrganizationID: organizationID,
			Email:          row.Email,
			Password:       row.Password,
			DisplayName:    row.DisplayName,
			Phone:          row.Phone,
		})
		if err != nil {
			res.Failed++
			// Any other failure stays generic: its cause can carry internal detail.
			rowErr := BulkImportError{Line: line, Email: row.Email, Code: errs.CodeInternal, Message: "could not create user"}
			// errs.*.WithDetail returns a copy (no Unwrap/Is), so match on the
			// stable code rather than identity.
			if e := errs.As(err); e != nil && e.Code == errs.ErrAuthEmailExists.Code {
				rowErr.Code, rowErr.Field, rowErr.Message = e.Code, "email", "a user with this email already exists"
			} else if e != nil && e.Code == errs.CodeUserDomainManaged {
				rowErr.Code, rowErr.Field, rowErr.Message = e.Code, "email", e.Message
			} else if e != nil && (e.Code == errs.CodePlanLimit || e.Code == errs.CodeServerOverloaded) {
				// No seat left for the role, or no room to hash the password now.
				rowErr.Code, rowErr.Message = e.Code, e.Message
			} else if e != nil && isPasswordRefusal(e.Code) {
				// Name the rule the row's password broke, so the operator can
				// fix that row and resubmit it alone.
				rowErr.Code, rowErr.Field, rowErr.Message = e.Code, "password", e.Message
			}
			res.Errors = append(res.Errors, rowErr)
			continue
		}
		res.Succeeded++
		res.Created = append(res.Created, BulkCreatedUser{Line: line, Email: u.Email, ID: u.ID})
	}
	if res.Created == nil {
		res.Created = []BulkCreatedUser{}
	}
	return res
}

// isPasswordRefusal reports whether code is a refusal from the password check
// (the organization's rules, the offline baseline or the breach check).
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
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in BulkCreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Never let a caller import into an organization other than their own.
	if in.OrganizationID != uuid.Nil && in.OrganizationID != organizationID {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("cannot import users into another organization"))
		return
	}
	// Envelope validation (batch size); per-row validation happens inside
	// runBulkImport so one bad row doesn't reject the whole batch.
	if err := h.Validate.Struct(in); err != nil {
		httpx.WriteError(w, r, httpx.ValidationError(err))
		return
	}
	var role *importRole
	if in.RoleID != nil {
		seats, err := h.checkImportRole(r, organizationID, *in.RoleID)
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		role = &importRole{ID: *in.RoleID, Seats: seats}
	}

	// Each row's password is checked against the organization's rules before its
	// user is written; a refused row is reported and the batch carries on.
	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		var hash string
		if ci.Password != "" {
			ph, herr := h.hashNewPassword(ctx, organizationID, ci.Email, ci.Password)
			if herr != nil {
				return nil, herr
			}
			hash = ph
		}
		return h.accounts().create(ctx, ci, hash, role, audit.ActorOf(r))
	}

	res := runBulkImport(r.Context(), h.Validate, organizationID, in.Users, create)
	if err := h.accounts().recordBulkImport(r.Context(), organizationID, res, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// checkImportRole refuses giving roleID to an import's users unless it is one
// of the organization's roles and the caller may give it: they hold role.write and
// the authority the role carries, as when assigning it to one person. It
// returns the organization's seat cap, which each user's role then counts against.
func (h *Handler) checkImportRole(r *http.Request, organizationID, roleID uuid.UUID) (int, error) {
	if h.Roles == nil {
		return 0, errs.ErrForbidden.WithDetail("roles can't be given here")
	}
	exists, err := h.Repo.q.RoleExistsInOrganization(r.Context(), dbgen.RoleExistsInOrganizationParams{ID: roleID, OrganizationID: organizationID})
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, errs.ErrRBACUserOrRoleNotFound
	}
	return h.Roles.CheckGrant(r, organizationID, roleID)
}

// bulkImportFromVendor handles POST /v1/users/bulk/import?source=auth0|cognito|azure_b2c.
// The body is the vendor's own export file, parsed by ParseVendorExport and
// imported like bulkCreate. Vendors don't export password hashes, so imported
// users have no password.
func (h *Handler) bulkImportFromVendor(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	source, ok := ParseImportSource(r.URL.Query().Get("source"))
	if !ok {
		httpx.WriteError(w, r, ErrImportSourceInvalid.WithDetail(importSourceHint()))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxImportBytes+1))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("could not read request body"))
		return
	}
	if len(raw) > maxImportBytes {
		httpx.WriteError(w, r, ErrImportFileTooLarge)
		return
	}

	rows, parseErrs := ParseVendorExport(source, raw)
	if len(rows) == 0 && len(parseErrs) == 0 {
		httpx.WriteError(w, r, ErrImportEmpty)
		return
	}
	if len(rows) > maxImportRows {
		httpx.WriteError(w, r, ErrImportBatchTooLarge)
		return
	}

	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		return h.accounts().create(ctx, ci, "", nil, audit.ActorOf(r))
	}
	res := runBulkImport(r.Context(), h.Validate, organizationID, rows, create)
	// Parse-level failures (rows that never reached validation) count toward
	// the same summary, with their own line numbers from the source file.
	res.Failed += len(parseErrs)
	res.Errors = append(parseErrs, res.Errors...)

	if err := h.accounts().recordBulkImport(r.Context(), organizationID, res, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
