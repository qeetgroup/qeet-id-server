package apikey

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeInvalid = "apikey.invalid"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrInvalid      = errs.New(CodeInvalid, errs.KindUnauthenticated, "Invalid API key.")
	ErrExpired      = errs.New("apikey.expired", errs.KindUnauthenticated, "This API key has expired.")
	ErrNameRequired = errs.New("apikey.name_required", errs.KindUnprocessable, "Enter a name for the API key.")
	ErrInvalidID    = errs.New("apikey.invalid_id", errs.KindInvalid, "That identifier isn't valid.")
	ErrUserNotSelf  = errs.New("apikey.user_not_self", errs.KindForbidden, "An API key can act only for the person who creates it.")
)
