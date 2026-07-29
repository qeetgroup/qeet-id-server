package errs

// Generic, cross-cutting PLATFORM error codes + errors. These aren't tied to a
// business domain — they're the framework/transport vocabulary used everywhere
// (validation, auth, rate limiting, the unhandled-error fallback). Business
// errors live in the per-domain files (mfa.go, auth.go, recovery.go, …).

const (
	CodeBadRequest      = "bad_request"
	CodeUnauthorized    = "unauthorized"
	CodeForbidden       = "forbidden"
	CodeStepUpRequired  = "step_up_required"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeUnprocessable   = "unprocessable"
	CodeValidation      = "validation_failed"
	CodeTooManyRequests = "too_many_requests"
	CodeInternal        = "internal"
	CodeNotImplemented  = "not_implemented"
)

// Default user-facing messages for each generic error — the fallback shown when
// a handler doesn't attach a more specific WithMessage. Keep them friendly and
// safe to show any end user. Change wording here; it's the single source of
// truth for the generic case. HTTP status for these codes lives in
// internal/platform/http.
var (
	ErrBadRequest       = New(CodeBadRequest, "The request was invalid.")
	ErrUnauthorized     = New(CodeUnauthorized, "Please sign in to continue.")
	ErrForbidden        = New(CodeForbidden, "You don't have permission to do that.")
	ErrStepUpRequired   = New(CodeStepUpRequired, "Additional verification is required to continue.")
	ErrNotFound         = New(CodeNotFound, "We couldn't find what you're looking for.")
	ErrConflict         = New(CodeConflict, "That conflicts with something that already exists.")
	ErrUnprocessable    = New(CodeUnprocessable, "We couldn't process that request.")
	ErrValidationFailed = New(CodeValidation, "One or more fields are invalid.")
	ErrTooManyRequests  = New(CodeTooManyRequests, "Too many attempts. Please wait and try again.").AsRetryable()
	ErrInternalServer   = New(CodeInternal, "Something went wrong on our end. Please try again.").AsRetryable()
	ErrNotImplemented   = New(CodeNotImplemented, "That feature isn't available yet.")
)
