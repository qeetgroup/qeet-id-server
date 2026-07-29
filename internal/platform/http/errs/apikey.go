package errs

// API-key error codes — stable, namespaced machine identifiers for the
// internal/developer/api-keys domain. Clients branch and localize on these
// (never on the message text). Once shipped, a code MUST NOT change. Every
// identifier is prefixed with the `apikey` domain so it never collides with
// another bounded context.
const (
	CodeAPIKeyNotFound     = "apikey.not_found"
	CodeAPIKeyInvalid      = "apikey.invalid"
	CodeAPIKeyExpired      = "apikey.expired"
	CodeAPIKeyNameRequired = "apikey.name_required"
	CodeAPIKeyInvalidID    = "apikey.invalid_id"
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
)
