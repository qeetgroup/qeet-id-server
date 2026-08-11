package errs

// Social-login (external OIDC identity provider) error codes — stable,
// namespaced machine identifiers for the tenant-configured social providers and
// the browser-facing authorization-code ceremony. Clients branch and localize
// on these, never on the message text. Once shipped, a code MUST NOT change.
const (
	CodeSocialTenantRequired        = "social.tenant_required"
	CodeSocialTenantNotFound        = "social.tenant_not_found"
	CodeSocialProviderNotConfigured = "social.provider_not_configured"
	CodeSocialProviderDisabled      = "social.provider_disabled"
	CodeSocialProviderNoDiscovery   = "social.provider_no_discovery"
	CodeSocialDiscoveryFailed       = "social.discovery_failed"
	CodeSocialCallbackParamsMissing = "social.callback_params_missing"
	CodeSocialStateInvalid          = "social.state_invalid"
	CodeSocialProviderMismatch      = "social.provider_mismatch"
	CodeSocialStateExpired          = "social.state_expired"
	CodeSocialTokenExchangeFailed   = "social.token_exchange_failed"
	CodeSocialUserinfoFailed        = "social.userinfo_failed"
	CodeSocialEmailMissing          = "social.email_missing"
	CodeSocialCodeRequired          = "social.code_required"
	CodeSocialLoginCodeInvalid      = "social.login_code_invalid"
	CodeSocialLoginCodeUsed         = "social.login_code_used"
	CodeSocialLoginCodeExpired      = "social.login_code_expired"
	CodeSocialAlreadyLinked         = "social.already_linked"
	CodeSocialNoAccount             = "social.no_account"
)

// Social-login errors. The Message is what the end user sees. Transient upstream
// failures and expired/invalid ceremony tokens are marked retryable — the client
// can safely restart the sign-in ceremony.
var (
	ErrSocialTenantRequired        = New(CodeSocialTenantRequired, "We couldn't determine which organization to sign you in to.")
	ErrSocialTenantNotFound        = New(CodeSocialTenantNotFound, "We couldn't find that organization.")
	ErrSocialProviderNotConfigured = New(CodeSocialProviderNotConfigured, "That sign-in provider isn't set up for this organization.")
	ErrSocialProviderDisabled      = New(CodeSocialProviderDisabled, "That sign-in provider is currently disabled.")
	ErrSocialProviderNoDiscovery   = New(CodeSocialProviderNoDiscovery, "That sign-in provider isn't fully configured. Contact your administrator.")
	ErrSocialDiscoveryFailed       = New(CodeSocialDiscoveryFailed, "We couldn't reach the sign-in provider. Please try again.").AsRetryable()
	ErrSocialCallbackParamsMissing = New(CodeSocialCallbackParamsMissing, "This sign-in request is missing required information.")
	ErrSocialStateInvalid          = New(CodeSocialStateInvalid, "This sign-in session is invalid. Please start again.").AsRetryable()
	ErrSocialProviderMismatch      = New(CodeSocialProviderMismatch, "This sign-in request doesn't match the provider. Please start again.")
	ErrSocialStateExpired          = New(CodeSocialStateExpired, "This sign-in session has expired. Please start again.").AsRetryable()
	ErrSocialTokenExchangeFailed   = New(CodeSocialTokenExchangeFailed, "We couldn't complete sign-in with the provider. Please try again.").AsRetryable()
	ErrSocialUserinfoFailed        = New(CodeSocialUserinfoFailed, "We couldn't retrieve your profile from the provider. Please try again.").AsRetryable()
	ErrSocialEmailMissing          = New(CodeSocialEmailMissing, "The sign-in provider didn't share an email address, which is required.")
	ErrSocialCodeRequired          = New(CodeSocialCodeRequired, "A sign-in code is required.")
	ErrSocialLoginCodeInvalid      = New(CodeSocialLoginCodeInvalid, "That sign-in code is invalid. Please start again.").AsRetryable()
	ErrSocialLoginCodeUsed         = New(CodeSocialLoginCodeUsed, "That sign-in code has already been used. Please start again.")
	ErrSocialLoginCodeExpired      = New(CodeSocialLoginCodeExpired, "That sign-in code has expired. Please start again.").AsRetryable()
	ErrSocialAlreadyLinked         = New(CodeSocialAlreadyLinked, "That account is already linked to a different Qeet ID.")
	ErrSocialNoAccount             = New(CodeSocialNoAccount, "No Qeet ID account uses that provider yet. Sign up first.")
)
