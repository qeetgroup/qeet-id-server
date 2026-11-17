package errs

// Data retention error codes.
const (
	CodeRetentionOrganizationInvalid  = "retention.tenant_invalid"
	CodeRetentionOrganizationMismatch = "retention.tenant_mismatch"
)

var (
	ErrRetentionOrganizationInvalid  = New(CodeRetentionOrganizationInvalid, "That tenant reference is invalid.")
	ErrRetentionOrganizationMismatch = New(CodeRetentionOrganizationMismatch, "You can't access another tenant's retention settings.")
)
