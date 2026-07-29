package errs

// SAML federation error codes — stable, namespaced machine identifiers for both
// the SP side (Qeet consuming an external IdP) and the IdP side (Qeet as an SSO
// source for downstream Service Providers). Clients branch/localize on the code,
// never the message. Once shipped, a code MUST NOT change.
const (
	CodeSAMLTenantIDInvalid          = "saml.tenant_id_invalid"
	CodeSAMLTenantMismatch           = "saml.tenant_mismatch"
	CodeSAMLIDInvalid                = "saml.id_invalid"
	CodeSAMLLoginCodeRequired        = "saml.login_code_required"
	CodeSAMLLoginCodeInvalid         = "saml.login_code_invalid"
	CodeSAMLLoginCodeUsed            = "saml.login_code_used"
	CodeSAMLLoginCodeExpired         = "saml.login_code_expired"
	CodeSAMLConnectionFieldsRequired = "saml.connection_fields_required"
	CodeSAMLCertificateInvalid       = "saml.certificate_invalid"
	CodeSAMLStatusInvalid            = "saml.status_invalid"
	CodeSAMLConnectionDisabled       = "saml.connection_disabled"
	CodeSAMLConnectionMisconfigured  = "saml.connection_misconfigured"
	CodeSAMLRequestInvalid           = "saml.request_invalid"
	CodeSAMLResponseMissing          = "saml.response_missing"
	CodeSAMLAssertionInvalid         = "saml.assertion_invalid"
	CodeSAMLAssertionConditions      = "saml.assertion_conditions"
	CodeSAMLAssertionNoEmail         = "saml.assertion_no_email"
	CodeSAMLIdPNotConfigured         = "saml.idp_not_configured"
	CodeSAMLAuthnRequestInvalid      = "saml.authn_request_invalid"
	CodeSAMLRequestParamMissing      = "saml.request_param_missing"
	CodeSAMLServiceProviderDisabled  = "saml.service_provider_disabled"
	CodeSAMLACSMismatch              = "saml.acs_url_mismatch"
	CodeSAMLSPFieldsRequired         = "saml.sp_fields_required"
	CodeSAMLUserTenantMismatch       = "saml.user_tenant_mismatch"
)

// SAML errors. Message is the end-user-facing text; edit wording here. Handlers
// just `return errs.ErrSAML<Reason>` (optionally `.Wrap(err)` for logs).
var (
	ErrSAMLTenantIDInvalid          = New(CodeSAMLTenantIDInvalid, "The tenant in the URL isn't valid.")
	ErrSAMLTenantMismatch           = New(CodeSAMLTenantMismatch, "You can only manage SAML settings for your own tenant.")
	ErrSAMLIDInvalid                = New(CodeSAMLIDInvalid, "That SAML resource ID isn't valid.")
	ErrSAMLLoginCodeRequired        = New(CodeSAMLLoginCodeRequired, "A sign-in code is required.")
	ErrSAMLLoginCodeInvalid         = New(CodeSAMLLoginCodeInvalid, "That sign-in code is invalid. Please sign in again.")
	ErrSAMLLoginCodeUsed            = New(CodeSAMLLoginCodeUsed, "That sign-in code has already been used. Please sign in again.")
	ErrSAMLLoginCodeExpired         = New(CodeSAMLLoginCodeExpired, "That sign-in code has expired. Please sign in again.")
	ErrSAMLConnectionFieldsRequired = New(CodeSAMLConnectionFieldsRequired, "Name, IdP entity ID, SSO URL and signing certificate are all required.")
	ErrSAMLCertificateInvalid       = New(CodeSAMLCertificateInvalid, "The signing certificate isn't a valid X.509 certificate.")
	ErrSAMLStatusInvalid            = New(CodeSAMLStatusInvalid, "Status must be draft, active or disabled.")
	ErrSAMLConnectionDisabled       = New(CodeSAMLConnectionDisabled, "This SAML connection is disabled.")
	ErrSAMLConnectionMisconfigured  = New(CodeSAMLConnectionMisconfigured, "This SAML connection isn't configured correctly. Contact your administrator.")
	ErrSAMLRequestInvalid           = New(CodeSAMLRequestInvalid, "The SAML request was malformed.")
	ErrSAMLResponseMissing          = New(CodeSAMLResponseMissing, "The SAML response is missing.")
	ErrSAMLAssertionInvalid         = New(CodeSAMLAssertionInvalid, "We couldn't validate the SAML assertion.")
	ErrSAMLAssertionConditions      = New(CodeSAMLAssertionConditions, "The SAML assertion is expired or wasn't intended for this service. Please sign in again.").AsRetryable()
	ErrSAMLAssertionNoEmail         = New(CodeSAMLAssertionNoEmail, "The SAML assertion didn't include an email address.")
	ErrSAMLIdPNotConfigured         = New(CodeSAMLIdPNotConfigured, "SAML identity-provider mode isn't available.")
	ErrSAMLAuthnRequestInvalid      = New(CodeSAMLAuthnRequestInvalid, "The SAMLRequest couldn't be read.")
	ErrSAMLRequestParamMissing      = New(CodeSAMLRequestParamMissing, "A SAMLRequest or sp parameter is required.")
	ErrSAMLServiceProviderDisabled  = New(CodeSAMLServiceProviderDisabled, "This service provider is disabled.")
	ErrSAMLACSMismatch              = New(CodeSAMLACSMismatch, "The assertion consumer service URL doesn't match the registered value.")
	ErrSAMLSPFieldsRequired         = New(CodeSAMLSPFieldsRequired, "Name, entity ID and ACS URL are all required.")
	ErrSAMLUserTenantMismatch       = New(CodeSAMLUserTenantMismatch, "You aren't a member of this service provider's tenant.")
)
