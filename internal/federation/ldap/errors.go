package ldap

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeServiceBindFailed        = "ldap.service_bind_failed"
	CodeCredentialsRequired      = "ldap.credentials_required"
	CodeEmailAttributeMissing    = "ldap.email_attribute_missing"
	CodeConnectionDisabled       = "ldap.connection_disabled"
	CodeConnectionFieldsRequired = "ldap.connection_fields_required"
	CodeServerURLInvalid         = "ldap.server_url_invalid"
	CodeStatusInvalid            = "ldap.status_invalid"
	CodeAccountNotInOrganization = "ldap.account_not_in_organization"
	CodeTLSVerifyRequired        = "ldap.tls_verify_required"
	CodeAccountAdministers       = "ldap.account_administers"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrDialFailed               = errs.New("ldap.dial_failed", errs.KindUnprocessable, "We couldn't reach the directory server. Please try again.").AsRetryable()
	ErrServiceBindFailed        = errs.New(CodeServiceBindFailed, errs.KindUnprocessable, "We couldn't connect to the directory with the configured service account.")
	ErrCredentialsRequired      = errs.New(CodeCredentialsRequired, errs.KindInvalid, "Enter your username and password.")
	ErrDirectoryUnreachable     = errs.New("ldap.directory_unreachable", errs.KindUnprocessable, "We couldn't reach the directory server. Please try again.").AsRetryable()
	ErrInvalidCredentials       = errs.New("ldap.invalid_credentials", errs.KindUnauthenticated, "That username or password is incorrect.")
	ErrEmailAttributeMissing    = errs.New(CodeEmailAttributeMissing, errs.KindUnprocessable, "Your directory account doesn't have an email address, which is required.")
	ErrConnectionDisabled       = errs.New(CodeConnectionDisabled, errs.KindForbidden, "This directory connection is disabled.")
	ErrConnectionDraft          = errs.New("ldap.connection_draft", errs.KindForbidden, "This directory connection is still being set up. Ask your administrator to turn it on.")
	ErrConnectionFieldsRequired = errs.New(CodeConnectionFieldsRequired, errs.KindUnprocessable, "Name, server URL, bind DN, bind password and base DN are required.")
	ErrServerURLInvalid         = errs.New(CodeServerURLInvalid, errs.KindUnprocessable, "The server URL must start with ldap:// or ldaps://.")
	ErrStatusInvalid            = errs.New(CodeStatusInvalid, errs.KindUnprocessable, "Status must be draft, active or disabled.")
	ErrAccountNotInOrganization = errs.New(CodeAccountNotInOrganization, errs.KindForbidden, "That directory account belongs to a different organization.") // a directory never adopts another organization's account
	ErrAccountUnverified        = errs.New("ldap.account_unverified", errs.KindForbidden, "An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with your directory account.")
	ErrTLSVerifyRequired        = errs.New(CodeTLSVerifyRequired, errs.KindUnprocessable, "Directory connections must verify the server's certificate. Turn off skip_tls_verify and give the server a certificate it can be verified with.")
	ErrEmailDomainUnverified    = errs.New("ldap.email_domain_unverified", errs.KindForbidden, "Your directory account's email address isn't on a domain this organization has verified. Ask your administrator to verify it.")
	ErrAccountAdministers       = errs.New(CodeAccountAdministers, errs.KindForbidden, "This account administers the organization, so a directory sign-in can't take it over by its email address. Sign in with the account's own password or passkey.")
	ErrJITNotAllowed            = errs.New("ldap.jit_not_allowed", errs.KindForbidden, "There's no account for this address, and your organization doesn't create one at sign-in for it. Ask your administrator to invite you.")
)
