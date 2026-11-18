package errs

// The generic errors: the framework's own vocabulary (validation, sign-in, rate
// limiting, the unhandled-error fallback). An error one package returns is
// declared in that package.

const (
	CodeBadRequest       = "bad_request"
	CodeUnauthorized     = "unauthorized"
	CodeForbidden        = "forbidden"
	CodeStepUpRequired   = "step_up_required"
	CodeNotFound         = "not_found"
	CodeUnprocessable    = "unprocessable"
	CodeValidation       = "validation_failed"
	CodeTooManyRequests  = "too_many_requests"
	CodeInternal         = "internal"
	CodeServerOverloaded = "server.overloaded"
)

// Default messages for the generic errors, shown when a handler doesn't set a
// more specific one with WithMessage. They must be safe to show any user.
var (
	ErrBadRequest          = New(CodeBadRequest, KindInvalid, "The request was invalid.")
	ErrUnauthorized        = New(CodeUnauthorized, KindUnauthenticated, "Please sign in to continue.")
	ErrForbidden           = New(CodeForbidden, KindForbidden, "You don't have permission to do that.")
	ErrStepUpRequired      = New(CodeStepUpRequired, KindForbidden, "Additional verification is required to continue.")
	ErrNotFound            = New(CodeNotFound, KindNotFound, "We couldn't find what you're looking for.")
	ErrConflict            = New("conflict", KindConflict, "That conflicts with something that already exists.")
	ErrUnprocessable       = New(CodeUnprocessable, KindUnprocessable, "We couldn't process that request.")
	ErrValidationFailed    = New(CodeValidation, KindUnprocessable, "One or more fields are invalid.")
	ErrTooManyRequests     = New(CodeTooManyRequests, KindTooManyRequests, "Too many attempts. Please wait and try again.").AsRetryable()
	ErrRequestBodyTooLarge = New("request_body_too_large", KindTooLarge, "The request body is too large.")
	ErrInternalServer      = New(CodeInternal, KindInternal, "Something went wrong on our end. Please try again.").AsRetryable()
	ErrNotImplemented      = New("not_implemented", KindNotImplemented, "That feature isn't available yet.")
)

// ErrServerOverloaded refuses work the server is too busy to take on now, such
// as a password hash while every hashing slot and its queue are full. It is
// answered 503 with Retry-After.
var ErrServerOverloaded = New(CodeServerOverloaded, KindUnavailable, "The service is busy. Please try again in a moment.").AsRetryable()
