package oidcsso

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeIDInvalid                = "oidc_connection.id_invalid"
	CodeFieldsRequired           = "oidc_connection.fields_required"
	CodeIssuerInvalid            = "oidc_connection.issuer_invalid"
	CodeDiscoveryURLInvalid      = "oidc_connection.discovery_url_invalid"
	CodeScopesInvalid            = "oidc_connection.scopes_invalid"
	CodeClaimInvalid             = "oidc_connection.claim_invalid"
	CodeTenantIDsInvalid         = "oidc_connection.idp_tenant_ids_invalid"
	CodeTenantIDsRequired        = "oidc_connection.idp_tenant_ids_required"
	CodeStatusInvalid            = "oidc_connection.status_invalid"
	CodeConnectionDraft          = "oidc_connection.connection_draft"
	CodeConnectionDisabled       = "oidc_connection.connection_disabled"
	CodeMisconfigured            = "oidc_connection.misconfigured"
	CodeStateInvalid             = "oidc_connection.state_invalid"
	CodeOtherBrowser             = "oidc_connection.other_browser"
	CodeProviderRefused          = "oidc_connection.provider_refused"
	CodeTokenExchangeFailed      = "oidc_connection.token_exchange_failed"
	CodeEmailUnverified          = "oidc_connection.email_unverified"
	CodeEmailDomainUnverified    = "oidc_connection.email_domain_unverified"
	CodeUserOrganizationMismatch = "oidc_connection.user_organization_mismatch"
	CodeAccountUnverified        = "oidc_connection.account_unverified"
	CodeAccountAdministers       = "oidc_connection.account_administers"
	CodeJITNotAllowed            = "oidc_connection.jit_not_allowed"
	CodeLoginCodeRequired        = "oidc_connection.login_code_required"
	CodeLoginCodeInvalid         = "oidc_connection.login_code_invalid"
	CodeLoginCodeUsed            = "oidc_connection.login_code_used"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrIDInvalid                = errs.New(CodeIDInvalid, errs.KindInvalid, "That OpenID Connect connection ID isn't valid.")
	ErrFieldsRequired           = errs.New(CodeFieldsRequired, errs.KindUnprocessable, "Name, issuer, client ID and client secret are all required.")
	ErrIssuerInvalid            = errs.New(CodeIssuerInvalid, errs.KindUnprocessable, "The issuer must be an absolute https:// URL without a query, fragment, user name or password.")
	ErrDiscoveryURLInvalid      = errs.New(CodeDiscoveryURLInvalid, errs.KindUnprocessable, "The discovery URL must be an absolute https:// URL without a fragment, user name or password.")
	ErrScopesInvalid            = errs.New(CodeScopesInvalid, errs.KindUnprocessable, "Scopes must be up to 20 single words, and include openid.")
	ErrClaimInvalid             = errs.New(CodeClaimInvalid, errs.KindUnprocessable, "Claim names must be single words of up to 100 characters, and the email claim is required.")
	ErrTenantIDsInvalid         = errs.New(CodeTenantIDsInvalid, errs.KindUnprocessable, "Allowed identity-provider tenant IDs must be GUIDs, up to 50 of them.")
	ErrTenantIDsRequired        = errs.New(CodeTenantIDsRequired, errs.KindUnprocessable, "This issuer signs in accounts from any organization. List the identity-provider tenant IDs to accept.")
	ErrStatusInvalid            = errs.New(CodeStatusInvalid, errs.KindUnprocessable, "Status must be draft, active or disabled.")
	ErrConnectionDraft          = errs.New(CodeConnectionDraft, errs.KindForbidden, "This single sign-on connection is still being set up. Ask your administrator to turn it on.")
	ErrConnectionDisabled       = errs.New(CodeConnectionDisabled, errs.KindForbidden, "This single sign-on connection is disabled.")
	ErrMisconfigured            = errs.New(CodeMisconfigured, errs.KindInternal, "This single sign-on connection isn't configured correctly. Contact your administrator.")
	ErrProviderUnreachable      = errs.New("oidc_connection.provider_unreachable", errs.KindBadGateway, "We couldn't reach your organization's sign-in provider. Please try again.").AsRetryable()
	ErrCallbackInvalid          = errs.New("oidc_connection.callback_invalid", errs.KindInvalid, "This sign-in response is missing required information.")
	ErrStateInvalid             = errs.New(CodeStateInvalid, errs.KindInvalid, "This sign-in is unknown, has expired, or was already completed. Please sign in again.").AsRetryable()
	ErrOtherBrowser             = errs.New(CodeOtherBrowser, errs.KindForbidden, "This sign-in was started in another browser. Sign in again from the browser you are using.")
	ErrProviderRefused          = errs.New(CodeProviderRefused, errs.KindUnauthenticated, "Your organization's sign-in provider didn't sign you in. Please try again, or contact your administrator.")
	ErrTokenExchangeFailed      = errs.New(CodeTokenExchangeFailed, errs.KindBadGateway, "We couldn't complete sign-in with your organization's provider. Please try again.").AsRetryable()
	ErrNoEmail                  = errs.New("oidc_connection.no_email", errs.KindInvalid, "Your organization's sign-in provider didn't share an email address, which is required.")
	ErrEmailUnverified          = errs.New(CodeEmailUnverified, errs.KindForbidden, "Your organization's sign-in provider says your email address isn't verified, so it can't sign you in.")
	ErrEmailDomainUnverified    = errs.New(CodeEmailDomainUnverified, errs.KindForbidden, "Single sign-on can't sign in this address: its domain isn't one this organization has verified. Ask your administrator to verify it.")
	ErrUserOrganizationMismatch = errs.New(CodeUserOrganizationMismatch, errs.KindForbidden, "You aren't a member of the organization this sign-in provider serves.")
	ErrAccountUnverified        = errs.New(CodeAccountUnverified, errs.KindForbidden, "An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with single sign-on.")
	ErrJITNotAllowed            = errs.New(CodeJITNotAllowed, errs.KindForbidden, "There's no account for this address, and your organization doesn't create one at sign-in for it. Ask your administrator to invite you.")
	ErrAccountAdministers       = errs.New(CodeAccountAdministers, errs.KindForbidden, "This account administers the organization, so single sign-on can't take it over by its email address. Sign in with the account's own password or passkey.")
	ErrLoginCodeRequired        = errs.New(CodeLoginCodeRequired, errs.KindInvalid, "A sign-in code is required.")
	ErrReturnToInvalid          = errs.New("oidc_connection.return_to_invalid", errs.KindInvalid, "That return address isn't allowed. Start signing in again from the application.")
	ErrLoginCodeInvalid         = errs.New(CodeLoginCodeInvalid, errs.KindUnauthenticated, "That sign-in code is invalid. Please sign in again.")
	ErrLoginCodeUsed            = errs.New(CodeLoginCodeUsed, errs.KindUnauthenticated, "That sign-in code has already been used. Please sign in again.")
	ErrLoginCodeExpired         = errs.New("oidc_connection.login_code_expired", errs.KindUnauthenticated, "That sign-in code has expired. Please sign in again.")
)
