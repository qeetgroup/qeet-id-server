package saml

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeIDInvalid                = "saml.id_invalid"
	CodeLoginCodeRequired        = "saml.login_code_required"
	CodeLoginCodeInvalid         = "saml.login_code_invalid"
	CodeLoginCodeUsed            = "saml.login_code_used"
	CodeLoginCodeExpired         = "saml.login_code_expired"
	CodeConnectionFieldsRequired = "saml.connection_fields_required"
	CodeCertificateInvalid       = "saml.certificate_invalid"
	CodeSSOURLInvalid            = "saml.sso_url_invalid"
	CodeStatusInvalid            = "saml.status_invalid"
	CodeConnectionDisabled       = "saml.connection_disabled"
	CodeConnectionDraft          = "saml.connection_draft"
	CodeOtherBrowser             = "saml.other_browser"
	CodeConnectionMisconfigured  = "saml.connection_misconfigured"
	CodeReturnToInvalid          = "saml.return_to_invalid"
	CodeResponseMissing          = "saml.response_missing"
	CodeAssertionConditions      = "saml.assertion_conditions"
	CodeAssertionNoEmail         = "saml.assertion_no_email"
	CodeRequestCorrelation       = "saml.request_correlation_invalid"
	CodeReplayDetected           = "saml.replay_detected"
	CodeIdPNotConfigured         = "saml.idp_not_configured"
	CodeAuthnRequestInvalid      = "saml.authn_request_invalid"
	CodeRequestParamMissing      = "saml.request_param_missing"
	CodeServiceProviderDisabled  = "saml.service_provider_disabled"
	CodeServiceProviderDraft     = "saml.service_provider_draft"
	CodeACSMismatch              = "saml.acs_url_mismatch"
	CodeACSURLInvalid            = "saml.acs_url_invalid"
	CodeSPFieldsRequired         = "saml.sp_fields_required"
	CodeUserOrganizationMismatch = "saml.user_organization_mismatch"
	CodeAccountUnverified        = "saml.account_unverified"
	CodeEmailDomainUnverified    = "saml.email_domain_unverified"
	CodeAccountAdministers       = "saml.account_administers"
	CodeTestSignInNotFound       = "saml.test_sign_in_not_found"
	CodeJITNotAllowed            = "saml.jit_not_allowed"
	CodeCertificateExists        = "saml.certificate_exists"
	CodeCertificateLast          = "saml.certificate_last"
	CodeMetadataRequired         = "saml.metadata_required"
	CodeMetadataInvalid          = "saml.metadata_invalid"
	CodeMetadataURLInvalid       = "saml.metadata_url_invalid"
	CodeMetadataUnreachable      = "saml.metadata_unreachable"
	CodeCertificateUnused        = "saml.certificate_unused"
	CodeRequestSignatureInvalid  = "saml.request_signature_invalid"
	CodeConnectionIncomplete     = "saml.connection_incomplete"
	CodeNameIDFormatInvalid      = "saml.name_id_format_invalid"
	CodeNameIDAttributeInvalid   = "saml.name_id_attribute_invalid"
	CodeAttributesInvalid        = "saml.attributes_invalid"
	CodeNameIDUnavailable        = "saml.name_id_unavailable"
	CodeSPNotAssigned            = "saml.sp_not_assigned"
	CodeAssigneeNotFound         = "saml.assignee_not_found"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrIDInvalid                = errs.New(CodeIDInvalid, errs.KindInvalid, "That SAML resource ID isn't valid.")
	ErrLoginCodeRequired        = errs.New(CodeLoginCodeRequired, errs.KindInvalid, "A sign-in code is required.")
	ErrLoginCodeInvalid         = errs.New(CodeLoginCodeInvalid, errs.KindUnauthenticated, "That sign-in code is invalid. Please sign in again.")
	ErrLoginCodeUsed            = errs.New(CodeLoginCodeUsed, errs.KindUnauthenticated, "That sign-in code has already been used. Please sign in again.")
	ErrLoginCodeExpired         = errs.New(CodeLoginCodeExpired, errs.KindUnauthenticated, "That sign-in code has expired. Please sign in again.")
	ErrConnectionFieldsRequired = errs.New(CodeConnectionFieldsRequired, errs.KindUnprocessable, "Name, IdP entity ID, SSO URL and signing certificate are all required.")
	ErrCertificateInvalid       = errs.New(CodeCertificateInvalid, errs.KindUnprocessable, "The signing certificate isn't a valid X.509 certificate.")
	ErrSSOURLInvalid            = errs.New(CodeSSOURLInvalid, errs.KindUnprocessable, "The IdP SSO URL must be an absolute https:// URL without a user name or password.")
	ErrStatusInvalid            = errs.New(CodeStatusInvalid, errs.KindUnprocessable, "Status must be draft, active or disabled.")
	ErrConnectionDisabled       = errs.New(CodeConnectionDisabled, errs.KindForbidden, "This SAML connection is disabled.")
	ErrConnectionDraft          = errs.New(CodeConnectionDraft, errs.KindForbidden, "This SAML connection is still being set up. Ask your administrator to turn it on.")
	ErrOtherBrowser             = errs.New(CodeOtherBrowser, errs.KindForbidden, "This sign-in was started in another browser. Sign in again from the browser you are using.")
	ErrConnectionMisconfigured  = errs.New(CodeConnectionMisconfigured, errs.KindInternal, "This SAML connection isn't configured correctly. Contact your administrator.")
	ErrRequestInvalid           = errs.New("saml.request_invalid", errs.KindInvalid, "The SAML request was malformed.")
	ErrReturnToInvalid          = errs.New(CodeReturnToInvalid, errs.KindInvalid, "That return address isn't allowed. Start signing in again from the application.")
	ErrResponseMissing          = errs.New(CodeResponseMissing, errs.KindInvalid, "The SAML response is missing.")
	ErrAssertionConditions      = errs.New(CodeAssertionConditions, errs.KindUnauthenticated, "The SAML assertion is expired or wasn't intended for this service. Please sign in again.").AsRetryable()
	ErrAssertionNoEmail         = errs.New(CodeAssertionNoEmail, errs.KindInvalid, "The SAML assertion didn't include an email address.")
	ErrRequestCorrelation       = errs.New(CodeRequestCorrelation, errs.KindUnauthenticated, "The SAML sign-in request is missing, expired, or has already been used. Please sign in again.")
	ErrReplayDetected           = errs.New(CodeReplayDetected, errs.KindUnauthenticated, "This SAML response has already been used. Please sign in again.")
	ErrIdPNotConfigured         = errs.New(CodeIdPNotConfigured, errs.KindNotImplemented, "SAML identity-provider mode isn't available.")
	ErrAuthnRequestInvalid      = errs.New(CodeAuthnRequestInvalid, errs.KindInvalid, "The SAMLRequest couldn't be read.")
	ErrRequestParamMissing      = errs.New(CodeRequestParamMissing, errs.KindInvalid, "A SAMLRequest or sp parameter is required.")
	ErrServiceProviderDisabled  = errs.New(CodeServiceProviderDisabled, errs.KindForbidden, "This service provider is disabled.")
	ErrServiceProviderDraft     = errs.New(CodeServiceProviderDraft, errs.KindForbidden, "This app is still being set up, so it can't sign anyone in yet.")
	ErrACSMismatch              = errs.New(CodeACSMismatch, errs.KindInvalid, "The assertion consumer service URL doesn't match the registered value.")
	ErrACSURLInvalid            = errs.New(CodeACSURLInvalid, errs.KindUnprocessable, "The ACS URL must be an absolute https:// URL without a user name or password (http only on localhost).")
	ErrSPFieldsRequired         = errs.New(CodeSPFieldsRequired, errs.KindUnprocessable, "Name, entity ID and ACS URL are all required.")
	ErrUserOrganizationMismatch = errs.New(CodeUserOrganizationMismatch, errs.KindForbidden, "You aren't a member of this service provider's tenant.")
	ErrAccountUnverified        = errs.New(CodeAccountUnverified, errs.KindForbidden, "An account already uses this email address, but the address hasn't been verified. Verify it, or reset the password from the link we email you, then sign in with single sign-on.")
	ErrSPEntityIDTaken          = errs.New("saml.sp_entity_id_taken", errs.KindConflict, "A service provider with this entity ID is already registered.")
	ErrEmailDomainUnverified    = errs.New(CodeEmailDomainUnverified, errs.KindForbidden, "Single sign-on can't sign in this address: its domain isn't one this organization has verified. Ask your administrator to verify it.")
	ErrAccountAdministers       = errs.New(CodeAccountAdministers, errs.KindForbidden, "This account administers the organization, so single sign-on can't take it over by its email address. Sign in with the account's own password or passkey.")
	ErrTestSignInNotFound       = errs.New(CodeTestSignInNotFound, errs.KindNotFound, "We couldn't find that test sign-in. Start a new one.")
	ErrJITNotAllowed            = errs.New(CodeJITNotAllowed, errs.KindForbidden, "There's no account for this address, and your organization doesn't create one at sign-in for it. Ask your administrator to invite you.")
	ErrCertificateExists        = errs.New(CodeCertificateExists, errs.KindConflict, "This connection already trusts that certificate.")
	ErrCertificateLimit         = errs.New("saml.certificate_limit", errs.KindUnprocessable, "A connection can trust at most 8 signing certificates. Remove one first.")
	ErrCertificateLast          = errs.New(CodeCertificateLast, errs.KindConflict, "A connection needs at least one signing certificate. Add the new one before removing this one.")
	ErrMetadataRequired         = errs.New(CodeMetadataRequired, errs.KindUnprocessable, "Give either the identity provider's metadata URL or its metadata XML.")
	ErrMetadataInvalid          = errs.New(CodeMetadataInvalid, errs.KindUnprocessable, "The identity provider's metadata couldn't be used.")
	ErrMetadataURLInvalid       = errs.New(CodeMetadataURLInvalid, errs.KindUnprocessable, "The metadata URL must be an absolute https:// URL on a public address, without a user name or password.")
	ErrMetadataUnreachable      = errs.New(CodeMetadataUnreachable, errs.KindUnprocessable, "The identity provider's metadata couldn't be fetched from its URL.")
	ErrCertificateUnused        = errs.New(CodeCertificateUnused, errs.KindUnprocessable, "Say what the app's certificate is for: verifying its signed sign-in requests, encrypting its assertions, or both.")
	ErrCertificateRequired      = errs.New("saml.certificate_required", errs.KindUnprocessable, "Add the app's certificate to verify its sign-in requests or encrypt its assertions.")
	ErrEncryptionKeyUnsupported = errs.New("saml.encryption_key_unsupported", errs.KindUnprocessable, "Encrypting assertions needs a certificate with an RSA key.")
	ErrRequestSignatureInvalid  = errs.New(CodeRequestSignatureInvalid, errs.KindForbidden, "The app's sign-in request isn't signed with the certificate registered for it.")
	ErrConnectionIncomplete     = errs.New(CodeConnectionIncomplete, errs.KindUnprocessable, "Add the identity provider's entity ID, SSO URL and signing certificate before turning the connection on.")
	ErrNameIDFormatInvalid      = errs.New(CodeNameIDFormatInvalid, errs.KindUnprocessable, "The NameID format must be emailAddress, persistent or unspecified.")
	ErrNameIDAttributeInvalid   = errs.New(CodeNameIDAttributeInvalid, errs.KindUnprocessable, "The NameID must come from email, user_id, persistent_id or metadata.<key>; an emailAddress NameID is the email, and a persistent one persistent_id or user_id.")
	ErrAttributesInvalid        = errs.New(CodeAttributesInvalid, errs.KindUnprocessable, "Each attribute needs a unique name and a known source and name format.")
	ErrNameIDUnavailable        = errs.New(CodeNameIDUnavailable, errs.KindForbidden, "We can't sign you in to this app: your account has no value for the identifier it uses. Ask your administrator.")
	ErrSPNotAssigned            = errs.New(CodeSPNotAssigned, errs.KindForbidden, "You haven't been given access to this app. Ask your administrator to assign it to you.")
	ErrAssigneeNotFound         = errs.New(CodeAssigneeNotFound, errs.KindNotFound, "No person whose account belongs to this organization, and no group of it, has that ID.")
)
