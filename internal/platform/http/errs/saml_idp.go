package errs

// SAML identity-provider error codes: what an organisation's apps are told
// about a person, and who may sign in to them.
const (
	CodeSAMLNameIDFormatInvalid    = "saml.name_id_format_invalid"
	CodeSAMLNameIDAttributeInvalid = "saml.name_id_attribute_invalid"
	CodeSAMLAttributesInvalid      = "saml.attributes_invalid"
	CodeSAMLNameIDUnavailable      = "saml.name_id_unavailable"
	CodeSAMLSPNotAssigned          = "saml.sp_not_assigned"
	CodeSAMLAssigneeNotFound       = "saml.assignee_not_found"
)

// SAML identity-provider errors.
var (
	ErrSAMLNameIDFormatInvalid = New(CodeSAMLNameIDFormatInvalid,
		"The NameID format must be emailAddress, persistent or unspecified.")
	ErrSAMLNameIDAttributeInvalid = New(CodeSAMLNameIDAttributeInvalid,
		"The NameID must come from email, user_id, persistent_id or metadata.<key>; an emailAddress NameID is the email, and a persistent one persistent_id or user_id.")
	ErrSAMLAttributesInvalid = New(CodeSAMLAttributesInvalid,
		"Each attribute needs a unique name and a known source and name format.")
	ErrSAMLNameIDUnavailable = New(CodeSAMLNameIDUnavailable,
		"We can't sign you in to this app: your account has no value for the identifier it uses. Ask your administrator.")
	ErrSAMLSPNotAssigned = New(CodeSAMLSPNotAssigned,
		"You haven't been given access to this app. Ask your administrator to assign it to you.")
	ErrSAMLAssigneeNotFound = New(CodeSAMLAssigneeNotFound,
		"No person whose account belongs to this organization, and no group of it, has that ID.")
)
