package errs

// Error codes for an organisation's own OpenID Connect identity provider
// (enterprise OIDC connections): their administration and sign-in.
const (
	CodeOIDCSSOIDInvalid               = "oidc_connection.id_invalid"
	CodeOIDCSSOFieldsRequired          = "oidc_connection.fields_required"
	CodeOIDCSSOIssuerInvalid           = "oidc_connection.issuer_invalid"
	CodeOIDCSSODiscoveryURLInvalid     = "oidc_connection.discovery_url_invalid"
	CodeOIDCSSOScopesInvalid           = "oidc_connection.scopes_invalid"
	CodeOIDCSSOClaimInvalid            = "oidc_connection.claim_invalid"
	CodeOIDCSSOTenantIDsInvalid        = "oidc_connection.idp_tenant_ids_invalid"
	CodeOIDCSSOTenantIDsRequired       = "oidc_connection.idp_tenant_ids_required"
	CodeOIDCSSOStatusInvalid           = "oidc_connection.status_invalid"
	CodeOIDCSSOConnectionDraft         = "oidc_connection.connection_draft"
	CodeOIDCSSOConnectionDisabled      = "oidc_connection.connection_disabled"
	CodeOIDCSSOMisconfigured           = "oidc_connection.misconfigured"
	CodeOIDCSSOProviderUnreachable     = "oidc_connection.provider_unreachable"
	CodeOIDCSSOCallbackInvalid         = "oidc_connection.callback_invalid"
	CodeOIDCSSOStateInvalid            = "oidc_connection.state_invalid"
	CodeOIDCSSOOtherBrowser            = "oidc_connection.other_browser"
	CodeOIDCSSOProviderRefused         = "oidc_connection.provider_refused"
	CodeOIDCSSOTokenExchangeFailed     = "oidc_connection.token_exchange_failed"
	CodeOIDCSSOIDTokenInvalid          = "oidc_connection.id_token_invalid"
	CodeOIDCSSONoEmail                 = "oidc_connection.no_email"
	CodeOIDCSSOEmailUnverified         = "oidc_connection.email_unverified"
	CodeOIDCSSOEmailDomainUnverified   = "oidc_connection.email_domain_unverified"
	CodeOIDCSSOUserTenantMismatch      = "oidc_connection.user_tenant_mismatch"
	CodeOIDCSSOAccountUnverified       = "oidc_connection.account_unverified"
	CodeOIDCSSOAccountAdministers      = "oidc_connection.account_administers"
	CodeOIDCSSOLoginCodeRequired       = "oidc_connection.login_code_required"
	CodeOIDCSSOLoginCodeInvalid        = "oidc_connection.login_code_invalid"
	CodeOIDCSSOLoginCodeUsed           = "oidc_connection.login_code_used"
	CodeOIDCSSOLoginCodeExpired        = "oidc_connection.login_code_expired"
	CodeOIDCSSOSecretEncryptionMissing = "oidc_connection.secret_encryption_unavailable"
)

// Enterprise OIDC errors. Every way an ID token can fail validation answers
// ErrOIDCSSOIDTokenInvalid, so a caller learns nothing about which check failed.
var (
	ErrOIDCSSOIDInvalid      = New(CodeOIDCSSOIDInvalid, "That OpenID Connect connection ID isn't valid.")
	ErrOIDCSSOFieldsRequired = New(CodeOIDCSSOFieldsRequired, "Name, issuer, client ID and client secret are all required.")
	ErrOIDCSSOIssuerInvalid  = New(CodeOIDCSSOIssuerInvalid,
		"The issuer must be an absolute https:// URL without a query, fragment, user name or password.")
	ErrOIDCSSODiscoveryURLInvalid = New(CodeOIDCSSODiscoveryURLInvalid,
		"The discovery URL must be an absolute https:// URL without a fragment, user name or password.")
	ErrOIDCSSOScopesInvalid = New(CodeOIDCSSOScopesInvalid,
		"Scopes must be up to 20 single words, and include openid.")
	ErrOIDCSSOClaimInvalid = New(CodeOIDCSSOClaimInvalid,
		"Claim names must be single words of up to 100 characters, and the email claim is required.")
	ErrOIDCSSOTenantIDsInvalid = New(CodeOIDCSSOTenantIDsInvalid,
		"Allowed identity-provider tenant IDs must be GUIDs, up to 50 of them.")
	ErrOIDCSSOTenantIDsRequired = New(CodeOIDCSSOTenantIDsRequired,
		"This issuer signs in accounts from any organization. List the identity-provider tenant IDs to accept.")
	ErrOIDCSSOStatusInvalid       = New(CodeOIDCSSOStatusInvalid, "Status must be draft, active or disabled.")
	ErrOIDCSSOConnectionDraft     = New(CodeOIDCSSOConnectionDraft, "This single sign-on connection is still being set up. Ask your administrator to turn it on.")
	ErrOIDCSSOConnectionDisabled  = New(CodeOIDCSSOConnectionDisabled, "This single sign-on connection is disabled.")
	ErrOIDCSSOMisconfigured       = New(CodeOIDCSSOMisconfigured, "This single sign-on connection isn't configured correctly. Contact your administrator.")
	ErrOIDCSSOProviderUnreachable = New(CodeOIDCSSOProviderUnreachable, "We couldn't reach your organization's sign-in provider. Please try again.").AsRetryable()
	ErrOIDCSSOCallbackInvalid     = New(CodeOIDCSSOCallbackInvalid, "This sign-in response is missing required information.")
	ErrOIDCSSOStateInvalid        = New(CodeOIDCSSOStateInvalid,
		"This sign-in is unknown, has expired, or was already completed. Please sign in again.").AsRetryable()
	ErrOIDCSSOOtherBrowser = New(CodeOIDCSSOOtherBrowser,
		"This sign-in was started in another browser. Sign in again from the browser you are using.")
	ErrOIDCSSOProviderRefused = New(CodeOIDCSSOProviderRefused,
		"Your organization's sign-in provider didn't sign you in. Please try again, or contact your administrator.")
	ErrOIDCSSOTokenExchangeFailed = New(CodeOIDCSSOTokenExchangeFailed,
		"We couldn't complete sign-in with your organization's provider. Please try again.").AsRetryable()
	ErrOIDCSSOIDTokenInvalid  = New(CodeOIDCSSOIDTokenInvalid, "We couldn't validate the sign-in from your organization's provider.")
	ErrOIDCSSONoEmail         = New(CodeOIDCSSONoEmail, "Your organization's sign-in provider didn't share an email address, which is required.")
	ErrOIDCSSOEmailUnverified = New(CodeOIDCSSOEmailUnverified,
		"Your organization's sign-in provider says your email address isn't verified, so it can't sign you in.")
	ErrOIDCSSOEmailDomainUnverified = New(CodeOIDCSSOEmailDomainUnverified,
		"Single sign-on can't sign in this address: its domain isn't one this organization has verified. Ask your administrator to verify it.")
	ErrOIDCSSOUserTenantMismatch = New(CodeOIDCSSOUserTenantMismatch, "You aren't a member of the organization this sign-in provider serves.")
	ErrOIDCSSOAccountUnverified  = New(CodeOIDCSSOAccountUnverified,
		"An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with single sign-on.")
	ErrOIDCSSOAccountAdministers = New(CodeOIDCSSOAccountAdministers,
		"This account administers the organization, so single sign-on can't take it over by its email address. Sign in with the account's own password or passkey.")
	ErrOIDCSSOLoginCodeRequired       = New(CodeOIDCSSOLoginCodeRequired, "A sign-in code is required.")
	ErrOIDCSSOLoginCodeInvalid        = New(CodeOIDCSSOLoginCodeInvalid, "That sign-in code is invalid. Please sign in again.")
	ErrOIDCSSOLoginCodeUsed           = New(CodeOIDCSSOLoginCodeUsed, "That sign-in code has already been used. Please sign in again.")
	ErrOIDCSSOLoginCodeExpired        = New(CodeOIDCSSOLoginCodeExpired, "That sign-in code has expired. Please sign in again.")
	ErrOIDCSSOSecretEncryptionMissing = New(CodeOIDCSSOSecretEncryptionMissing, "Connection secrets can't be stored right now. Contact support.")
)
