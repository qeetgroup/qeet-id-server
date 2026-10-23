package errs

// Data retention error codes.
const (
	CodeRetentionTenantInvalid  = "retention.tenant_invalid"
	CodeRetentionTenantMismatch = "retention.tenant_mismatch"
)

var (
	ErrRetentionTenantInvalid  = New(CodeRetentionTenantInvalid, "That tenant reference is invalid.")
	ErrRetentionTenantMismatch = New(CodeRetentionTenantMismatch, "You can't access another tenant's retention settings.")
)
