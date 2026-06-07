// Package errs defines the canonical error vocabulary for qeet-id.
// Each error carries a stable code that the HTTP layer maps to a status.
package errs

import (
	"errors"
	"fmt"
)

type Error struct {
	Code    string
	Status  int
	Message string
	Detail  string
	// Fields carries per-field validation messages keyed by the (JSON) field
	// name, e.g. {"email": "Must be a valid email address."}. Optional.
	Fields map[string]string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) WithDetail(d string) *Error {
	cp := *e
	cp.Detail = d
	return &cp
}

// WithMessage overrides the human-facing message while keeping the code and
// status, so a single canonical error can carry a context-specific, friendly
// message (e.g. "Invalid email or password.").
func (e *Error) WithMessage(m string) *Error {
	cp := *e
	cp.Message = m
	return &cp
}

// WithFields attaches per-field validation messages.
func (e *Error) WithFields(f map[string]string) *Error {
	cp := *e
	cp.Fields = f
	return &cp
}

func New(code string, status int, msg string) *Error {
	return &Error{Code: code, Status: status, Message: msg}
}

var (
	ErrBadRequest      = New("bad_request", 400, "invalid request")
	ErrUnauthorized    = New("unauthorized", 401, "authentication required")
	ErrForbidden       = New("forbidden", 403, "permission denied")
	ErrStepUpRequired  = New("step_up_required", 403, "recent multi-factor verification required")
	ErrNotFound        = New("not_found", 404, "resource not found")
	ErrConflict        = New("conflict", 409, "resource conflict")
	ErrUnprocessable   = New("unprocessable", 422, "request could not be processed")
	ErrValidation      = New("validation_failed", 422, "One or more fields are invalid.")
	ErrTooManyRequests = New("too_many_requests", 429, "too many requests")
	ErrInternal        = New("internal", 500, "internal server error")
	ErrNotImplemented  = New("not_implemented", 501, "feature not available")
)

func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
