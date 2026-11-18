package errs

// Token-vault error codes — the per-organization encrypted store for third-party
// OAuth tokens (Slack, GitHub, Google, …). Stable, namespaced machine
// identifiers; clients branch and localize on these, never on the message text.
const (
	CodeTokenVaultGrantNotFound = "tokenvault.grant_not_found"
)

// Token-vault errors. The Message is what the end user sees. Handlers just
// `return errs.ErrTokenVaultGrantNotFound`, attaching a wrapped cause with
// `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrTokenVaultGrantNotFound = New(CodeTokenVaultGrantNotFound, KindNotFound, "No connected account was found for this provider.")
)
