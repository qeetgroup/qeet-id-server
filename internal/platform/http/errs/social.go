package errs

// Social login (external OIDC provider) error codes.
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
	CodeSocialAccountNotInTenant    = "social.account_not_in_tenant"
	CodeSocialReturnToInvalid       = "social.return_to_invalid"
	CodeSocialEmailUnverified       = "social.email_unverified"
	CodeSocialAccountUnverified     = "social.account_unverified"
	CodeSocialCodeRequired          = "social.code_required"
	CodeSocialLoginCodeInvalid      = "social.login_code_invalid"
	CodeSocialLoginCodeUsed         = "social.login_code_used"
	CodeSocialLoginCodeExpired      = "social.login_code_expired"
	CodeSocialAlreadyLinked         = "social.already_linked"
	CodeSocialNoAccount             = "social.no_account"
	CodeSocialProviderInUse         = "social.provider_in_use"
	CodeSocialBrowserMismatch       = "social.browser_mismatch"
	CodeSocialLinkCodeInvalid       = "social.link_code_invalid"
	CodeSocialLinkAccountMismatch   = "social.link_account_mismatch"
)

// Social login errors; ceremony and upstream failures are retryable.
// ErrSocialProviderNotConfigured also covers a switched-off provider, and
// ErrSocialAccountNotInTenant is vague so it reveals no other tenant's address.
// ErrSocialProviderDisabled is no longer returned; its code stays reserved.
var (
	ErrSocialTenantRequired        = New(CodeSocialTenantRequired, "We couldn't determine which organization to sign you in to.")
	ErrSocialTenantNotFound        = New(CodeSocialTenantNotFound, "We couldn't find that organization.")
	ErrSocialProviderNotConfigured = New(CodeSocialProviderNotConfigured, "That sign-in option isn't available for this organization.")
	ErrSocialProviderDisabled      = New(CodeSocialProviderDisabled, "That sign-in provider is currently disabled.")
	ErrSocialProviderInUse         = New(CodeSocialProviderInUse, "Some people can sign in only with this provider. Switch it off instead, or give them another way to sign in first.")
	ErrSocialProviderNoDiscovery   = New(CodeSocialProviderNoDiscovery, "That sign-in provider isn't fully configured. Contact your administrator.")
	ErrSocialDiscoveryFailed       = New(CodeSocialDiscoveryFailed, "We couldn't reach the sign-in provider. Please try again.").AsRetryable()
	ErrSocialCallbackParamsMissing = New(CodeSocialCallbackParamsMissing, "This sign-in request is missing required information.")
	ErrSocialStateInvalid          = New(CodeSocialStateInvalid, "This sign-in session is invalid. Please start again.").AsRetryable()
	ErrSocialProviderMismatch      = New(CodeSocialProviderMismatch, "This sign-in request doesn't match the provider. Please start again.")
	ErrSocialStateExpired          = New(CodeSocialStateExpired, "This sign-in session has expired. Please start again.").AsRetryable()
	ErrSocialTokenExchangeFailed   = New(CodeSocialTokenExchangeFailed, "We couldn't complete sign-in with the provider. Please try again.").AsRetryable()
	ErrSocialUserinfoFailed        = New(CodeSocialUserinfoFailed, "We couldn't retrieve your profile from the provider. Please try again.").AsRetryable()
	ErrSocialEmailMissing          = New(CodeSocialEmailMissing, "The sign-in provider didn't share an email address, which is required.")
	ErrSocialReturnToInvalid       = New(CodeSocialReturnToInvalid,
		"That sign-in link has an invalid return address.")

	ErrSocialAccountNotInTenant = New(CodeSocialAccountNotInTenant,
		"That account can't sign in with this provider.")
	ErrSocialEmailUnverified   = New(CodeSocialEmailUnverified, "The sign-in provider did not verify ownership of that email address. Link it from a signed-in account instead.")
	ErrSocialAccountUnverified = New(CodeSocialAccountUnverified,
		"An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with this provider.")
	ErrSocialCodeRequired     = New(CodeSocialCodeRequired, "A sign-in code is required.")
	ErrSocialLoginCodeInvalid = New(CodeSocialLoginCodeInvalid, "That sign-in code is invalid. Please start again.").AsRetryable()
	ErrSocialLoginCodeUsed    = New(CodeSocialLoginCodeUsed, "That sign-in code has already been used. Please start again.")
	ErrSocialLoginCodeExpired = New(CodeSocialLoginCodeExpired, "That sign-in code has expired. Please start again.").AsRetryable()
	ErrSocialAlreadyLinked    = New(CodeSocialAlreadyLinked, "That account is already linked to a different Qeet ID.")
	ErrSocialNoAccount        = New(CodeSocialNoAccount, "No Qeet ID account uses that provider yet. Sign up first.")

	ErrSocialBrowserMismatch = New(CodeSocialBrowserMismatch,
		"This sign-in was started in a different browser. Please start again here.").AsRetryable()
	ErrSocialLinkCodeInvalid = New(CodeSocialLinkCodeInvalid,
		"That connection has expired or was already completed. Please connect the account again.").AsRetryable()
	ErrSocialLinkAccountMismatch = New(CodeSocialLinkAccountMismatch,
		"This connection was started from a different account.")
)
