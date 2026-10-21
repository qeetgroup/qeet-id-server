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

// Social-login errors. The Message is what the end user sees. Transient upstream
// failures and expired/invalid ceremony tokens are marked retryable — the client
// can safely restart the sign-in ceremony.
var (
	ErrSocialTenantRequired = New(CodeSocialTenantRequired, "We couldn't determine which organization to sign you in to.")
	ErrSocialTenantNotFound = New(CodeSocialTenantNotFound, "We couldn't find that organization.")
	// ErrSocialProviderNotConfigured is also the answer for a provider the
	// organisation has switched off, so sign-in does not reveal which.
	ErrSocialProviderNotConfigured = New(CodeSocialProviderNotConfigured, "That sign-in option isn't available for this organization.")
	// ErrSocialProviderDisabled is no longer returned (a switched-off provider
	// reads as not set up); the code stays reserved so it is never reused.
	ErrSocialProviderDisabled = New(CodeSocialProviderDisabled, "That sign-in provider is currently disabled.")
	// ErrSocialProviderInUse refuses removing a provider some people can sign
	// in only through; metadata.people says how many.
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
	// Deliberately vague: emails are globally unique, so a precise message here
	// would confirm to one tenant that an address belongs to another.
	// ErrSocialReturnToInvalid rejects a hosted-flow return_to that is neither a
	// root-relative path nor an allowlisted origin — it would be an open
	// redirect on the authentication domain.
	ErrSocialReturnToInvalid = New(CodeSocialReturnToInvalid,
		"That sign-in link has an invalid return address.")

	ErrSocialAccountNotInTenant = New(CodeSocialAccountNotInTenant,
		"That account can't sign in with this provider.")
	ErrSocialEmailUnverified = New(CodeSocialEmailUnverified, "The sign-in provider did not verify ownership of that email address. Link it from a signed-in account instead.")
	// ErrSocialAccountUnverified: an account already uses the address, but
	// nobody has proved they own it there, so a provider vouching for the
	// address doesn't hand that account over — it may have been registered by
	// someone else.
	ErrSocialAccountUnverified = New(CodeSocialAccountUnverified,
		"An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with this provider.")
	ErrSocialCodeRequired     = New(CodeSocialCodeRequired, "A sign-in code is required.")
	ErrSocialLoginCodeInvalid = New(CodeSocialLoginCodeInvalid, "That sign-in code is invalid. Please start again.").AsRetryable()
	ErrSocialLoginCodeUsed    = New(CodeSocialLoginCodeUsed, "That sign-in code has already been used. Please start again.")
	ErrSocialLoginCodeExpired = New(CodeSocialLoginCodeExpired, "That sign-in code has expired. Please start again.").AsRetryable()
	ErrSocialAlreadyLinked    = New(CodeSocialAlreadyLinked, "That account is already linked to a different Qeet ID.")
	ErrSocialNoAccount        = New(CodeSocialNoAccount, "No Qeet ID account uses that provider yet. Sign up first.")

	// ErrSocialBrowserMismatch refuses a provider callback in a browser that
	// didn't begin the sign-in: a link someone else began would otherwise sign
	// this browser in to their account.
	ErrSocialBrowserMismatch = New(CodeSocialBrowserMismatch,
		"This sign-in was started in a different browser. Please start again here.").AsRetryable()
	// ErrSocialLinkCodeInvalid: the code that completes connecting a provider
	// is unknown, used or expired.
	ErrSocialLinkCodeInvalid = New(CodeSocialLinkCodeInvalid,
		"That connection has expired or was already completed. Please connect the account again.").AsRetryable()
	// ErrSocialLinkAccountMismatch: connecting a provider is completed only by
	// the account that began it, so a connect link sent to someone else can't
	// attach their provider account to the sender's.
	ErrSocialLinkAccountMismatch = New(CodeSocialLinkAccountMismatch,
		"This connection was started from a different account.")
)
