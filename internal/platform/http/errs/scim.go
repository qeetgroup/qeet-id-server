package errs

// SCIM provisioning error codes — stable, namespaced machine identifiers for the
// tenant-scoped SCIM admin surface. Clients branch/localize on the code, never
// the message. Once shipped, a code MUST NOT change. (The SCIM 2.0 protocol
// surface itself emits the RFC 7644 error envelope, not these catalog errors.)
const (
	CodeSCIMTenantIDInvalid = "scim.tenant_id_invalid"
	CodeSCIMTenantMismatch  = "scim.tenant_mismatch"
)

// SCIM errors. Message is the end-user-facing text; edit wording here.
var (
	ErrSCIMTenantIDInvalid = New(CodeSCIMTenantIDInvalid, "The tenant in the URL isn't valid.")
	ErrSCIMTenantMismatch  = New(CodeSCIMTenantMismatch, "You can only manage SCIM settings for your own tenant.")
)
