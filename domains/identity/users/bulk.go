package user

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/api/rest/errs"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
	"github.com/qeetgroup/qeet-id/platform/security/encryption"
)

// maxImportBytes bounds a raw vendor-export upload (NDJSON/CSV/JSON).
const maxImportBytes = 10 * 1024 * 1024

// maxImportRows mirrors BulkCreateInput's own batch-size ceiling.
const maxImportRows = 1000

// userCreator creates one user (hashing + persistence). Injected into
// runBulkImport so the aggregation logic is unit-testable without a DB.
type userCreator func(ctx context.Context, in CreateInput) (*User, error)

// runBulkImport validates and creates each row, continuing past per-row
// failures (partial success). It returns the summary plus the users that were
// created, so the caller can emit created events. HTTP/DB specifics are kept
// out — `create` is injected — so this is pure and testable.
func runBulkImport(ctx context.Context, v *validator.Validate, tenantID uuid.UUID, rows []BulkUserInput, create userCreator) (BulkImportResult, []*User) {
	var res BulkImportResult
	created := make([]*User, 0, len(rows))
	for i, row := range rows {
		line := i + 1
		if v != nil {
			if err := v.Struct(row); err != nil {
				res.Failed++
				res.Errors = append(res.Errors, BulkImportError{Line: line, Email: row.Email, Message: "invalid row: " + firstValidationMsg(err)})
				continue
			}
		}
		u, err := create(ctx, CreateInput{
			TenantID:    tenantID,
			Email:       row.Email,
			Password:    row.Password,
			DisplayName: row.DisplayName,
			Phone:       row.Phone,
		})
		if err != nil {
			res.Failed++
			msg := "could not create user"
			// errs.*.WithDetail returns a copy (no Unwrap/Is), so match on the
			// stable code rather than identity.
			if e := errs.As(err); e != nil && e.Code == errs.ErrConflict.Code {
				msg = "a user with this email already exists"
			}
			res.Errors = append(res.Errors, BulkImportError{Line: line, Email: row.Email, Message: msg})
			continue
		}
		res.Succeeded++
		created = append(created, u)
	}
	return res, created
}

// firstValidationMsg renders a concise message from a validator error.
func firstValidationMsg(err error) string {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) && len(ve) > 0 {
		return ve[0].Field() + " failed " + ve[0].Tag()
	}
	return "validation failed"
}

// bulkCreate handles POST /v1/users/bulk. Admin-gated on user.write (see
// permissionMap). Each row is attempted independently — a bad or duplicate row
// is reported in the response rather than failing the whole batch.
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

	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		var hash string
		if ci.Password != "" {
			ph, herr := password.Hash(ci.Password)
			if herr != nil {
				return nil, herr
			}
			hash = ph
		}
		return h.Repo.CreateWithCredential(ctx, ci, hash)
	}

	res, created := runBulkImport(r.Context(), h.Validate, tenantID, in.Users, create)
	for _, u := range created {
		h.publishCreated(r, u) // audit user.created + outbox, per created user
	}
	h.auditBulkImport(r, tenantID, res)
	httpx.WriteJSON(w, http.StatusOK, res)
}

// bulkImportFromVendor handles POST /v1/users/bulk/import?source=auth0|cognito|azure_b2c.
// The request body is that vendor's own raw user-export file (NDJSON/CSV/JSON
// per source — see import_adapters.go); it's converted to the same
// BulkUserInput shape bulkCreate accepts and run through the identical
// per-row partial-success pipeline. No vendor exports a portable password
// hash, so every imported row lands with no password credential (passkey,
// magic link, OTP, or an admin-triggered reset are how they first sign in).
func (h *Handler) bulkImportFromVendor(w http.ResponseWriter, r *http.Request) {
	tenantID, err := httpx.RequireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	source, ok := ParseImportSource(r.URL.Query().Get("source"))
	if !ok {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("unknown or missing source query param; "+importSourceHint()))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxImportBytes+1))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("could not read request body"))
		return
	}
	if len(raw) > maxImportBytes {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("export file too large"))
		return
	}

	rows, parseErrs := ParseVendorExport(source, raw)
	if len(rows) == 0 && len(parseErrs) == 0 {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("no user records found in the export"))
		return
	}
	if len(rows) > maxImportRows {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("import batch too large (max 1000 rows per request)"))
		return
	}

	create := func(ctx context.Context, ci CreateInput) (*User, error) {
		return h.Repo.CreateWithCredential(ctx, ci, "")
	}
	res, created := runBulkImport(r.Context(), h.Validate, tenantID, rows, create)
	// Parse-level failures (rows that never reached validation) count toward
	// the same summary, with their own line numbers from the source file.
	res.Failed += len(parseErrs)
	res.Errors = append(parseErrs, res.Errors...)

	for _, u := range created {
		h.publishCreated(r, u)
	}
	h.auditBulkImport(r, tenantID, res)
	httpx.WriteJSON(w, http.StatusOK, res)
}

// auditBulkImport records a single summary row for the batch.
func (h *Handler) auditBulkImport(r *http.Request, tenantID uuid.UUID, res BulkImportResult) {
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	tid := tenantID
	_ = audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		Action:       "user.bulk_imported",
		ResourceType: "user",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"succeeded": res.Succeeded, "failed": res.Failed},
	})
	_ = tx.Commit(ctx)
}
