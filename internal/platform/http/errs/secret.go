package errs

// Secret (per-tenant secrets vault) error codes — stable, namespaced machine
// identifiers. Clients branch and localize on these, never on the message text.
const (
	CodeSecretNotFound          = "secret.not_found"
	CodeSecretNameValueRequired = "secret.name_value_required"
	CodeSecretNameExists        = "secret.name_exists"
	CodeSecretValueRequired     = "secret.value_required"
	CodeSecretDecryptFailed     = "secret.decrypt_failed"
	CodeSecretScopeRequired     = "secret.scope_required"
)

// Secret vault errors. The Message is what the end user sees. Handlers just
// `return errs.ErrSecretNotFound`, attaching a wrapped cause with `.Wrap(err)`
// when there's an underlying error worth logging.
var (
	ErrSecretNotFound          = New(CodeSecretNotFound, "We couldn't find that secret.")
	ErrSecretNameValueRequired = New(CodeSecretNameValueRequired, "A secret name and value are required.")
	ErrSecretNameExists        = New(CodeSecretNameExists, "A secret with that name already exists.")
	ErrSecretValueRequired     = New(CodeSecretValueRequired, "A secret value is required.")
	// Deterministic (bad key/data) — retrying won't help, so not retryable.
	ErrSecretDecryptFailed = New(CodeSecretDecryptFailed, "We couldn't decrypt this secret.")
	ErrSecretScopeRequired = New(CodeSecretScopeRequired, "You don't have permission to access this secret.")
)
