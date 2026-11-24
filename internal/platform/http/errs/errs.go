// Package errs defines qeet-id's transport-agnostic errors. Each error has a
// stable, namespaced code that clients branch and localize on, never the
// message, and a kind that the HTTP layer maps to a status. A package declares
// its own errors; errors several packages return are declared here.
package errs

import (
	"errors"
	"sync"
)

// Kind is what kind of failure an error is. It says nothing about HTTP: the
// transport maps each kind to a status.
type Kind uint8

// The kinds of failure.
const (
	KindInvalid          Kind = iota + 1 // the request is malformed
	KindUnauthenticated                  // the caller isn't signed in, or the sign-in is no good
	KindPaymentRequired                  // the organization's plan or payment stands in the way
	KindForbidden                        // signed in, but not allowed
	KindNotFound                         // no such thing, or not the caller's to see
	KindConflict                         // the request clashes with what exists
	KindGone                             // it existed and is gone for good
	KindTooLarge                         // the request body is too large
	KindUnsupportedMedia                 // the request body isn't in a format accepted
	KindUnprocessable                    // well-formed, but the values aren't acceptable
	KindTooManyRequests                  // slow down
	KindInternal                         // the server failed
	KindNotImplemented                   // the server doesn't do this
	KindBadGateway                       // a service the server depends on failed
	KindUnavailable                      // the server can't answer now; try again later
)

// FieldError is a structured per-field validation error. `Code` is a stable,
// machine-readable reason (e.g. "required", "invalid_format") so clients can
// localize and react without parsing the human `Message`.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error is a transport-agnostic error: a stable code, a safe message, and
// optional detail, metadata and cause.
type Error struct {
	Code    string // stable machine identifier, e.g. "mfa.code_invalid"
	Kind    Kind   // what kind of failure it is; the transport maps it to a status
	Message string // human-facing text shown to the end user
	Detail  string // optional developer context (never localized)
	// TranslationKey is the i18n key a client SDK can localize on. Defaults to
	// Code (which is already a stable `domain.reason` key); override only if a
	// different key namespace is needed.
	TranslationKey string
	// Retryable (`retryable: true`) tells the person they can try again, often by starting over: signing
	// in again, asking for a new code, waiting. It doesn't promise a resend succeeds (a revoked session is
	// retryable and never comes back); clients decide resends from the status (429, 503 + Retry-After).
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

// Wrap attaches err as the cause, kept for logs and never shown to users. It
// returns e unchanged when err is nil:
//
//	return authentication.ErrSessionInvalid.Wrap(dbErr)
func (e *Error) Wrap(err error) *Error {
	if err == nil {
		return e
	}
	cp := *e
	cp.cause = err
	return &cp
}

// AsRetryable returns a copy marked retryable: the person can try again (see Retryable).
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

// New declares an error: its stable code, its kind and the message people see.
// Declare each error once, in a package-level var of the package that returns
// it; New panics on a code declared before. TranslationKey defaults to Code.
func New(code string, kind Kind, msg string) *Error {
	e := &Error{Code: code, Kind: kind, Message: msg, TranslationKey: code}
	if _, dup := declared.LoadOrStore(code, e); dup {
		panic("errs: error code " + code + " is declared twice")
	}
	return e
}

// declared holds every error New made, by code.
var declared sync.Map

// Lookup returns the error declared with code.
func Lookup(code string) (*Error, bool) {
	e, ok := declared.Load(code)
	if !ok {
		return nil, false
	}
	return e.(*Error), true
}

// As returns the *Error in err's chain, or nil.
func As(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
