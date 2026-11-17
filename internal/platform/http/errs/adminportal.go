package errs

// Admin Portal error codes: the time-limited link an organization admin gives an IT
// admin to configure SAML or SCIM.
const (
	// Capabilities.
	CodeAdminPortalCapabilitiesRequired = "adminportal.capabilities_required"
	CodeAdminPortalCapabilityUnknown    = "adminportal.capability_unknown"
	CodeAdminPortalCapabilityNotGranted = "adminportal.capability_not_granted"

	// Link lifetime.
	CodeAdminPortalTTLOutOfRange = "adminportal.ttl_out_of_range"

	// Link lifecycle.
	CodeAdminPortalLinkNotFound   = "adminportal.link_not_found"
	CodeAdminPortalTokenMissing   = "adminportal.token_missing"
	CodeAdminPortalLinkInvalid    = "adminportal.link_invalid"
	CodeAdminPortalLinkRevoked    = "adminportal.link_revoked"
	CodeAdminPortalLinkExpired    = "adminportal.link_expired"
	CodeAdminPortalSessionMissing = "adminportal.session_missing"
	CodeAdminPortalSessionInvalid = "adminportal.session_invalid"

	// Request shape & path parameters.
	CodeAdminPortalOrganizationIDInvalid = "adminportal.tenant_id_invalid"
	CodeAdminPortalOrganizationMismatch  = "adminportal.tenant_mismatch"
	CodeAdminPortalActorRequired         = "adminportal.actor_required"
	CodeAdminPortalIDInvalid             = "adminportal.id_invalid"

	// SAML connection input.
	CodeAdminPortalSAMLFieldsRequired = "adminportal.saml_fields_required"
	CodeAdminPortalSAMLStatusInvalid  = "adminportal.saml_status_invalid"
)

// Admin Portal errors. The Message is what the end user sees — edit wording
// here, in one place. Handlers just `return errs.ErrAdminPortal…`, attaching a
// wrapped cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	// Capabilities.
	ErrAdminPortalCapabilitiesRequired = New(CodeAdminPortalCapabilitiesRequired, `Choose at least one capability ("saml", "scim" or "domain_verification").`)
	ErrAdminPortalCapabilityUnknown    = New(CodeAdminPortalCapabilityUnknown, `Unknown capability (must be "saml", "scim" or "domain_verification").`)
	ErrAdminPortalCapabilityNotGranted = New(CodeAdminPortalCapabilityNotGranted, "This admin portal link doesn't include that access.")

	// Link lifetime.
	ErrAdminPortalTTLOutOfRange = New(CodeAdminPortalTTLOutOfRange, "A setup link lasts between 15 minutes and 24 hours.")

	// Link lifecycle.
	ErrAdminPortalLinkNotFound   = New(CodeAdminPortalLinkNotFound, "We couldn't find that admin portal link.")
	ErrAdminPortalTokenMissing   = New(CodeAdminPortalTokenMissing, "This admin portal link is missing its token.")
	ErrAdminPortalLinkInvalid    = New(CodeAdminPortalLinkInvalid, "This admin portal link is invalid.")
	ErrAdminPortalLinkRevoked    = New(CodeAdminPortalLinkRevoked, "This admin portal link has been revoked.")
	ErrAdminPortalLinkExpired    = New(CodeAdminPortalLinkExpired, "This admin portal link has expired. Ask for a new one.")
	ErrAdminPortalSessionMissing = New(CodeAdminPortalSessionMissing, "An admin portal session is required.")
	ErrAdminPortalSessionInvalid = New(CodeAdminPortalSessionInvalid, "This admin portal session is invalid or expired. Ask for a new link.")

	// Request shape & path parameters.
	ErrAdminPortalOrganizationIDInvalid = New(CodeAdminPortalOrganizationIDInvalid, "That tenant ID is invalid.")
	ErrAdminPortalOrganizationMismatch  = New(CodeAdminPortalOrganizationMismatch, "You can only access your own tenant.")
	ErrAdminPortalActorRequired         = New(CodeAdminPortalActorRequired, "This action must be attributed to a signed-in user.")
	ErrAdminPortalIDInvalid             = New(CodeAdminPortalIDInvalid, "That ID is invalid.")

	// SAML connection input.
	ErrAdminPortalSAMLFieldsRequired = New(CodeAdminPortalSAMLFieldsRequired, "Name the connection, and give the IdP entity ID, SSO URL and certificate together (none of them makes a draft).")
	ErrAdminPortalSAMLStatusInvalid  = New(CodeAdminPortalSAMLStatusInvalid, "Status must be draft, active or disabled.")
)
