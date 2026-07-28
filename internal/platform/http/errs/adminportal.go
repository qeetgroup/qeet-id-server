package errs

// Admin Portal error codes — stable, namespaced machine identifiers for the
// federation/adminportal bounded context (the time-limited, capability-scoped
// link a tenant admin hands to an account-less IT admin to configure SAML/SCIM).
// Clients branch and localize on these codes, never on the message text. Once
// shipped a code MUST NOT change. Every name is prefixed `AdminPortal` so it
// never collides with another domain's catalog.
const (
	// Capabilities.
	CodeAdminPortalCapabilitiesRequired = "adminportal.capabilities_required"
	CodeAdminPortalCapabilityUnknown    = "adminportal.capability_unknown"
	CodeAdminPortalCapabilityNotGranted = "adminportal.capability_not_granted"

	// Link lifecycle.
	CodeAdminPortalLinkNotFound = "adminportal.link_not_found"
	CodeAdminPortalTokenMissing = "adminportal.token_missing"
	CodeAdminPortalLinkInvalid  = "adminportal.link_invalid"
	CodeAdminPortalLinkRevoked  = "adminportal.link_revoked"
	CodeAdminPortalLinkExpired  = "adminportal.link_expired"

	// Request shape & path parameters.
	CodeAdminPortalTenantIDInvalid = "adminportal.tenant_id_invalid"
	CodeAdminPortalTenantMismatch  = "adminportal.tenant_mismatch"
	CodeAdminPortalActorRequired   = "adminportal.actor_required"
	CodeAdminPortalIDInvalid       = "adminportal.id_invalid"

	// SAML connection input.
	CodeAdminPortalSAMLFieldsRequired = "adminportal.saml_fields_required"
	CodeAdminPortalSAMLStatusInvalid  = "adminportal.saml_status_invalid"
)

// Admin Portal errors. The Message is what the end user sees — edit wording
// here, in one place. Handlers just `return errs.ErrAdminPortal…`, attaching a
// wrapped cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	// Capabilities.
	ErrAdminPortalCapabilitiesRequired = New(CodeAdminPortalCapabilitiesRequired, `Choose at least one capability ("saml", "scim", or both).`)
	ErrAdminPortalCapabilityUnknown    = New(CodeAdminPortalCapabilityUnknown, `Unknown capability (must be "saml" or "scim").`)
	ErrAdminPortalCapabilityNotGranted = New(CodeAdminPortalCapabilityNotGranted, "This admin portal link doesn't include that access.")

	// Link lifecycle.
	ErrAdminPortalLinkNotFound = New(CodeAdminPortalLinkNotFound, "We couldn't find that admin portal link.")
	ErrAdminPortalTokenMissing = New(CodeAdminPortalTokenMissing, "This admin portal link is missing its token.")
	ErrAdminPortalLinkInvalid  = New(CodeAdminPortalLinkInvalid, "This admin portal link is invalid.")
	ErrAdminPortalLinkRevoked  = New(CodeAdminPortalLinkRevoked, "This admin portal link has been revoked.")
	ErrAdminPortalLinkExpired  = New(CodeAdminPortalLinkExpired, "This admin portal link has expired. Ask for a new one.")

	// Request shape & path parameters.
	ErrAdminPortalTenantIDInvalid = New(CodeAdminPortalTenantIDInvalid, "That tenant ID is invalid.")
	ErrAdminPortalTenantMismatch  = New(CodeAdminPortalTenantMismatch, "You can only access your own tenant.")
	ErrAdminPortalActorRequired   = New(CodeAdminPortalActorRequired, "This action must be attributed to a signed-in user.")
	ErrAdminPortalIDInvalid       = New(CodeAdminPortalIDInvalid, "That ID is invalid.")

	// SAML connection input.
	ErrAdminPortalSAMLFieldsRequired = New(CodeAdminPortalSAMLFieldsRequired, "Name, IdP entity ID, IdP SSO URL and IdP certificate are all required.")
	ErrAdminPortalSAMLStatusInvalid  = New(CodeAdminPortalSAMLStatusInvalid, "Status must be draft, active or disabled.")
)
