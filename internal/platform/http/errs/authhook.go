package errs

// Auth-hook error codes — stable, namespaced machine identifiers for the
// internal/developer/auth-hooks domain. Clients branch and localize on these
// (never on the message text). Once shipped, a code MUST NOT change. Every
// identifier is prefixed with the `authhook` domain so it never collides with
// another bounded context.
const (
	CodeAuthHookNotFound       = "authhook.not_found"
	CodeAuthHookDenied         = "authhook.denied"
	CodeAuthHookURLInvalid     = "authhook.url_invalid"
	CodeAuthHookInvalidID      = "authhook.invalid_id"
	CodeAuthHookTenantMismatch = "authhook.tenant_mismatch"
)

// Auth-hook errors. The Message is what the end user sees — edit wording here,
// in one place. ErrAuthHookDenied carries a safe default; the Run path overrides
// it with the tenant policy's own message via WithMessage when one is supplied.
var (
	ErrAuthHookNotFound       = New(CodeAuthHookNotFound, "That auth hook doesn't exist.")
	ErrAuthHookDenied         = New(CodeAuthHookDenied, "Sign-in was blocked by your organization's policy.")
	ErrAuthHookURLInvalid     = New(CodeAuthHookURLInvalid, "Enter an absolute http(s) URL for the auth hook.")
	ErrAuthHookInvalidID      = New(CodeAuthHookInvalidID, "That identifier isn't valid.")
	ErrAuthHookTenantMismatch = New(CodeAuthHookTenantMismatch, "You can only manage auth hooks in your own tenant.")
)
