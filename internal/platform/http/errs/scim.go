package errs

// SCIM provisioning admin error codes. The SCIM 2.0 protocol endpoints use the
// RFC 7644 error envelope instead.
const (
	CodeSCIMOrganizationIDInvalid = "scim.tenant_id_invalid"
	CodeSCIMOrganizationMismatch  = "scim.tenant_mismatch"
	CodeSCIMTokenIDInvalid        = "scim.token_id_invalid"
	CodeSCIMTokenNotFound         = "scim.token_not_found"
	CodeSCIMTokenNameInvalid      = "scim.token_name_invalid"
	CodeSCIMTokenExpiryInvalid    = "scim.token_expiry_invalid"
	CodeSCIMTokenOverlapInvalid   = "scim.token_overlap_invalid"
	CodeSCIMTokenInactive         = "scim.token_inactive"
	CodeSCIMTokenLimit            = "scim.token_limit"
)

// SCIM errors. Message is the end-user-facing text; edit wording here.
var (
	ErrSCIMOrganizationIDInvalid = New(CodeSCIMOrganizationIDInvalid, "The tenant in the URL isn't valid.")
	ErrSCIMOrganizationMismatch  = New(CodeSCIMOrganizationMismatch, "You can only manage SCIM settings for your own tenant.")
	ErrSCIMTokenIDInvalid        = New(CodeSCIMTokenIDInvalid, "That SCIM token identifier isn't valid.")
	ErrSCIMTokenNotFound         = New(CodeSCIMTokenNotFound, "That SCIM token doesn't exist or is already revoked.")
	ErrSCIMTokenNameInvalid      = New(CodeSCIMTokenNameInvalid, "Enter a name for the SCIM token, up to 200 characters.")
	ErrSCIMTokenExpiryInvalid    = New(CodeSCIMTokenExpiryInvalid, "A SCIM token's expiry must be in the future.")
	ErrSCIMTokenOverlapInvalid   = New(CodeSCIMTokenOverlapInvalid, "The overlap must be between 0 and 720 hours.")
	ErrSCIMTokenInactive         = New(CodeSCIMTokenInactive, "That SCIM token is revoked, expired or already rotated, so it can't be rotated.")
	ErrSCIMTokenLimit            = New(CodeSCIMTokenLimit, "This organisation has as many SCIM tokens as it can hold. Revoke one first.")
)
