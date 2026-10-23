package errs

// API key error codes.
const (
	CodeAPIKeyNotFound     = "apikey.not_found"
	CodeAPIKeyInvalid      = "apikey.invalid"
	CodeAPIKeyExpired      = "apikey.expired"
	CodeAPIKeyNameRequired = "apikey.name_required"
	CodeAPIKeyInvalidID    = "apikey.invalid_id"
	CodeAPIKeyUserNotSelf  = "apikey.user_not_self"
)

// API-key errors. The Message is what the end user sees — edit wording here, in
// one place. The presented-key failures (malformed, unknown, bad secret) share
// one message so a caller can't distinguish why a key was rejected.
var (
	ErrAPIKeyNotFound     = New(CodeAPIKeyNotFound, "That API key doesn't exist.")
	ErrAPIKeyInvalid      = New(CodeAPIKeyInvalid, "Invalid API key.")
	ErrAPIKeyExpired      = New(CodeAPIKeyExpired, "This API key has expired.")
	ErrAPIKeyNameRequired = New(CodeAPIKeyNameRequired, "Enter a name for the API key.")
	ErrAPIKeyInvalidID    = New(CodeAPIKeyInvalidID, "That identifier isn't valid.")
	ErrAPIKeyUserNotSelf  = New(CodeAPIKeyUserNotSelf, "An API key can act only for the person who creates it.")
)
