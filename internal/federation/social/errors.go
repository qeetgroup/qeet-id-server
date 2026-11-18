package social

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeAccountAdministers  = "social.account_administers"
	CodeLoginCodeInvalid    = "social.login_code_invalid"
	CodeProviderInUse       = "social.provider_in_use"
	CodeLinkCodeInvalid     = "social.link_code_invalid"
	CodeLinkAccountMismatch = "social.link_account_mismatch"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrOrganizationRequired  = errs.New("social.organization_required", errs.KindInvalid, "We couldn't determine which organization to sign you in to.")
	ErrOrganizationNotFound  = errs.New("social.organization_not_found", errs.KindNotFound, "We couldn't find that organization.")
	ErrProviderInUse         = errs.New(CodeProviderInUse, errs.KindConflict, "Some people can sign in only with this provider. Switch it off instead, or give them another way to sign in first.")
	ErrProviderNoDiscovery   = errs.New("social.provider_no_discovery", errs.KindInvalid, "That sign-in provider isn't fully configured. Contact your administrator.")
	ErrDiscoveryFailed       = errs.New("social.discovery_failed", errs.KindUnprocessable, "We couldn't reach the sign-in provider. Please try again.").AsRetryable()
	ErrCallbackParamsMissing = errs.New("social.callback_params_missing", errs.KindInvalid, "This sign-in request is missing required information.")
	ErrStateInvalid          = errs.New("social.state_invalid", errs.KindInvalid, "This sign-in session is invalid. Please start again.").AsRetryable()
	ErrProviderMismatch      = errs.New("social.provider_mismatch", errs.KindInvalid, "This sign-in request doesn't match the provider. Please start again.")
	ErrStateExpired          = errs.New("social.state_expired", errs.KindInvalid, "This sign-in session has expired. Please start again.").AsRetryable()
	ErrTokenExchangeFailed   = errs.New("social.token_exchange_failed", errs.KindUnprocessable, "We couldn't complete sign-in with the provider. Please try again.").AsRetryable()
	ErrUserinfoFailed        = errs.New("social.userinfo_failed", errs.KindUnprocessable, "We couldn't retrieve your profile from the provider. Please try again.").AsRetryable()
	ErrEmailMissing          = errs.New("social.email_missing", errs.KindInvalid, "The sign-in provider didn't share an email address, which is required.")
	ErrReturnToInvalid       = errs.New("social.return_to_invalid", errs.KindInvalid, "That sign-in link has an invalid return address.")
	ErrEmailUnverified       = errs.New("social.email_unverified", errs.KindForbidden, "The sign-in provider did not verify ownership of that email address. Link it from a signed-in account instead.")
	ErrAccountUnverified     = errs.New("social.account_unverified", errs.KindForbidden, "An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with this provider.")
	ErrAccountAdministers    = errs.New(CodeAccountAdministers, errs.KindForbidden, "This account administers the organization, so a sign-in provider can't take it over by its email address. Sign in with the account's own password or passkey, then connect the provider from your account.")
	ErrCodeRequired          = errs.New("social.code_required", errs.KindInvalid, "A sign-in code is required.")
	ErrLoginCodeInvalid      = errs.New(CodeLoginCodeInvalid, errs.KindUnauthenticated, "That sign-in code is invalid. Please start again.").AsRetryable()
	ErrLoginCodeUsed         = errs.New("social.login_code_used", errs.KindUnauthenticated, "That sign-in code has already been used. Please start again.")
	ErrLoginCodeExpired      = errs.New("social.login_code_expired", errs.KindUnauthenticated, "That sign-in code has expired. Please start again.").AsRetryable()
	ErrAlreadyLinked         = errs.New("social.already_linked", errs.KindConflict, "That account is already linked to a different Qeet ID.")
	ErrNoAccount             = errs.New("social.no_account", errs.KindNotFound, "No Qeet ID account uses that provider yet. Sign up first.")
	ErrBrowserMismatch       = errs.New("social.browser_mismatch", errs.KindForbidden, "This sign-in was started in a different browser. Please start again here.").AsRetryable()
	ErrLinkCodeInvalid       = errs.New(CodeLinkCodeInvalid, errs.KindInvalid, "That connection has expired or was already completed. Please connect the account again.").AsRetryable()
	ErrLinkAccountMismatch   = errs.New(CodeLinkAccountMismatch, errs.KindForbidden, "This connection was started from a different account.")
	// ErrProviderNotConfigured also covers a switched-off provider; ErrAccountNotInOrganization is
	// vague, so it reveals no other organization's address.
	ErrProviderNotConfigured    = errs.New("social.provider_not_configured", errs.KindNotFound, "That sign-in option isn't available for this organization.")
	ErrAccountNotInOrganization = errs.New("social.account_not_in_organization", errs.KindForbidden, "That account can't sign in with this provider.")
)
