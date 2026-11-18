package adminportal

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeCapabilityNotGranted = "adminportal.capability_not_granted"
	// Link lifetime.
	CodeTTLOutOfRange  = "adminportal.ttl_out_of_range"
	CodeLinkExpired    = "adminportal.link_expired"
	CodeSessionInvalid = "adminportal.session_invalid"
	// SAML connection input.
	CodeSAMLFieldsRequired = "adminportal.saml_fields_required"
	CodeSAMLStatusInvalid  = "adminportal.saml_status_invalid"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	// Capabilities.
	ErrCapabilitiesRequired = errs.New("adminportal.capabilities_required", errs.KindUnprocessable, `Choose at least one capability ("saml", "scim" or "domain_verification").`)
	ErrCapabilityUnknown    = errs.New("adminportal.capability_unknown", errs.KindUnprocessable, `Unknown capability (must be "saml", "scim" or "domain_verification").`)
	ErrCapabilityNotGranted = errs.New(CodeCapabilityNotGranted, errs.KindForbidden, "This admin portal link doesn't include that access.")
	// Link lifetime.
	ErrTTLOutOfRange = errs.New(CodeTTLOutOfRange, errs.KindUnprocessable, "A setup link lasts between 15 minutes and 24 hours.")
	// Link lifecycle.
	ErrLinkNotFound   = errs.New("adminportal.link_not_found", errs.KindNotFound, "We couldn't find that admin portal link.")
	ErrTokenMissing   = errs.New("adminportal.token_missing", errs.KindUnauthenticated, "This admin portal link is missing its token.")
	ErrLinkInvalid    = errs.New("adminportal.link_invalid", errs.KindUnauthenticated, "This admin portal link is invalid.")
	ErrLinkRevoked    = errs.New("adminportal.link_revoked", errs.KindUnauthenticated, "This admin portal link has been revoked.")
	ErrLinkExpired    = errs.New(CodeLinkExpired, errs.KindUnauthenticated, "This admin portal link has expired. Ask for a new one.")
	ErrSessionMissing = errs.New("adminportal.session_missing", errs.KindUnauthenticated, "An admin portal session is required.")
	ErrSessionInvalid = errs.New(CodeSessionInvalid, errs.KindUnauthenticated, "This admin portal session is invalid or expired. Ask for a new link.")
	// Request shape & path parameters.
	ErrActorRequired = errs.New("adminportal.actor_required", errs.KindUnauthenticated, "This action must be attributed to a signed-in user.")
	ErrIDInvalid     = errs.New("adminportal.id_invalid", errs.KindInvalid, "That ID is invalid.")
	// SAML connection input.
	ErrSAMLFieldsRequired = errs.New(CodeSAMLFieldsRequired, errs.KindUnprocessable, "Name the connection, and give the IdP entity ID, SSO URL and certificate together (none of them makes a draft).")
	ErrSAMLStatusInvalid  = errs.New(CodeSAMLStatusInvalid, errs.KindUnprocessable, "Status must be draft, active or disabled.")
)
