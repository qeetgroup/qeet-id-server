package errs

// SCIM provisioning admin error codes. The SCIM 2.0 protocol endpoints use the
// RFC 7644 error envelope instead.
const (
	CodeSCIMTenantIDInvalid = "scim.tenant_id_invalid"
	CodeSCIMTenantMismatch  = "scim.tenant_mismatch"
)

// SCIM errors. Message is the end-user-facing text; edit wording here.
var (
	ErrSCIMTenantIDInvalid = New(CodeSCIMTenantIDInvalid, "The tenant in the URL isn't valid.")
	ErrSCIMTenantMismatch  = New(CodeSCIMTenantMismatch, "You can only manage SCIM settings for your own tenant.")
)
