package errs

// Token-vault error codes — the per-organization encrypted store for third-party
// OAuth tokens (Slack, GitHub, Google, …). Stable, namespaced machine
// identifiers; clients branch and localize on these, never on the message text.
const (
	CodeTokenVaultProviderNotFound         = "tokenvault.provider_not_found"
	CodeTokenVaultProviderAuthorizeInvalid = "tokenvault.provider_authorize_url_invalid"
	CodeTokenVaultProviderInUse            = "tokenvault.provider_in_use"
	CodeTokenVaultProviderTokenURLInvalid  = "tokenvault.provider_token_url_invalid"
	CodeTokenVaultConnectStateInvalid      = "tokenvault.connect_state_invalid"
	CodeTokenVaultConnectExpired           = "tokenvault.connect_expired"
	CodeTokenVaultConnectOtherBrowser      = "tokenvault.connect_other_browser"
	CodeTokenVaultTokenExchangeFailed      = "tokenvault.token_exchange_failed"
	CodeTokenVaultGrantNotFound            = "tokenvault.grant_not_found"
	CodeTokenVaultTokenExpired             = "tokenvault.token_expired"
	CodeTokenVaultScopeRequired            = "tokenvault.scope_required"
	CodeTokenVaultPeopleOnly               = "tokenvault.people_only"
)

// Token-vault errors. The Message is what the end user sees. Handlers just
// `return errs.ErrTokenVaultGrantNotFound`, attaching a wrapped cause with
// `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrTokenVaultProviderNotFound         = New(CodeTokenVaultProviderNotFound, "That provider isn't registered for your account.")
	ErrTokenVaultProviderAuthorizeInvalid = New(CodeTokenVaultProviderAuthorizeInvalid, "This provider is misconfigured and can't be used to connect.")
	ErrTokenVaultProviderTokenURLInvalid  = New(CodeTokenVaultProviderTokenURLInvalid, "The provider's token URL must be a public http or https URL.")
	ErrTokenVaultProviderInUse            = New(CodeTokenVaultProviderInUse, "People are connected through this provider, so its endpoints and client can't change. Delete it to disconnect them first.")
	ErrTokenVaultConnectStateInvalid      = New(CodeTokenVaultConnectStateInvalid, "This connection link is invalid or has already been used. Please start again.")
	ErrTokenVaultConnectExpired           = New(CodeTokenVaultConnectExpired, "This connection request has expired. Please start again.")
	ErrTokenVaultConnectOtherBrowser      = New(CodeTokenVaultConnectOtherBrowser, "This connection was started in another browser. Start it again in the browser you are using.")
	ErrTokenVaultTokenExchangeFailed      = New(CodeTokenVaultTokenExchangeFailed, "We couldn't complete the connection with the provider. Please try again.").AsRetryable()
	ErrTokenVaultGrantNotFound            = New(CodeTokenVaultGrantNotFound, "No connected account was found for this provider.")
	ErrTokenVaultTokenExpired             = New(CodeTokenVaultTokenExpired, "Your connection to this provider has expired. Please reconnect your account.")
	ErrTokenVaultScopeRequired            = New(CodeTokenVaultScopeRequired, "You don't have permission to access this connected account.")
	ErrTokenVaultPeopleOnly               = New(CodeTokenVaultPeopleOnly, "Only the person who connected this account can read its token, while signed in.")
)
