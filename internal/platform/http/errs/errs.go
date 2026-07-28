// Package errs defines the canonical, transport-agnostic error vocabulary for
// qeet-id. Each error carries a stable machine code; the transport layer (see
// internal/platform/http) maps that code to an HTTP status, so these errors are
// reusable across HTTP, gRPC, CLI, jobs, and event consumers without any of
// them being baked into the domain error.
package errs

import (
	"errors"
)

// FieldError is a structured per-field validation error. `Code` is a stable,
// machine-readable reason (e.g. "required", "invalid_format") so clients can
// localize and react without parsing the human `Message`.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Error struct {
	Code    string // stable machine identifier, e.g. "mfa.code_invalid"
	Message string // human-facing text shown to the end user
	Detail  string // optional developer context (never localized)
	// TranslationKey is the i18n key a client SDK can localize on. Defaults to
	// Code (which is already a stable `domain.reason` key); override only if a
	// different key namespace is needed.
	TranslationKey string
	// Retryable signals the client may safely retry (e.g. refresh a session and
	// try again). Surfaced as `retryable: true`.
	Retryable bool
	// Fields carries structured per-field validation errors.
	Fields []FieldError
	// Metadata carries structured, machine-actionable context (e.g.
	// {"remaining_attempts": 2}) so clients act on data, not message text.
	Metadata map[string]any
	// cause is the wrapped underlying error (e.g. a pgx/driver error). Preserved
	// for logs via Error()/Unwrap(); NEVER serialized to the client.
	cause error
}

// Error returns the stable code (plus the wrapped cause when present) — the
// machine-facing string engineers see in logs. The human-facing Message is
// deliberately omitted: it's for end users, not log lines.
func (e *Error) Error() string {
	switch {
	case e.cause != nil:
		return e.Code + ": " + e.cause.Error()
	case e.Detail != "":
		return e.Code + ": " + e.Detail
	default:
		return e.Code
	}
}

// Unwrap exposes the wrapped cause so errors.Is / errors.As can see through it.
func (e *Error) Unwrap() error { return e.cause }

// Is matches by code, so errors.Is(err, errs.ErrUnauthorized) works regardless
// of any attached detail/cause/metadata copy.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.Code == t.Code
}

// Wrap attaches an underlying cause, kept for logs and never shown to users:
//
//	return errs.ErrAuthSessionInvalid.Wrap(dbErr)
//
// Wrapping nil is a no-op (returns the receiver unchanged, no allocation).
func (e *Error) Wrap(err error) *Error {
	if err == nil {
		return e
	}
	cp := *e
	cp.cause = err
	return &cp
}

// AsRetryable returns a copy marked retryable (client may back off + retry).
func (e *Error) AsRetryable() *Error {
	cp := *e
	cp.Retryable = true
	return &cp
}

// WithDetail attaches developer context (never localized/shown to users).
// An empty detail is a no-op (returns the receiver unchanged).
func (e *Error) WithDetail(d string) *Error {
	if d == "" {
		return e
	}
	cp := *e
	cp.Detail = d
	return &cp
}

// WithMessage overrides the human-facing message while keeping the code, so a
// single canonical error can carry a context-specific, friendly message.
func (e *Error) WithMessage(m string) *Error {
	cp := *e
	cp.Message = m
	return &cp
}

// WithTranslationKey overrides the i18n key (defaults to Code).
func (e *Error) WithTranslationKey(k string) *Error {
	cp := *e
	cp.TranslationKey = k
	return &cp
}

// WithFields attaches structured per-field validation errors (defensively
// copied so callers can't mutate a shared sentinel's slice).
func (e *Error) WithFields(f []FieldError) *Error {
	cp := *e
	cp.Fields = append([]FieldError(nil), f...)
	return &cp
}

// WithMetadata attaches structured, machine-actionable context (defensively
// copied so callers can't mutate a shared sentinel's map).
func (e *Error) WithMetadata(m map[string]any) *Error {
	cp := *e
	if m != nil {
		dst := make(map[string]any, len(m))
		for k, v := range m {
			dst[k] = v
		}
		cp.Metadata = dst
	}
	return &cp
}

// New builds a canonical error. Status is intentionally NOT stored here — the
// transport layer maps Code→status (see internal/platform/http statusByCode),
// keeping domain errors transport-agnostic. TranslationKey defaults to Code.
func New(code, msg string) *Error {
	return &Error{Code: code, Message: msg, TranslationKey: code}
}

func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
