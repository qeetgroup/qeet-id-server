package errs

// Analytics error codes.
const (
	CodeAnalyticsTenantInvalid  = "analytics.tenant_invalid"
	CodeAnalyticsTenantMismatch = "analytics.tenant_mismatch"
)

var (
	ErrAnalyticsTenantInvalid  = New(CodeAnalyticsTenantInvalid, "That tenant reference is invalid.")
	ErrAnalyticsTenantMismatch = New(CodeAnalyticsTenantMismatch, "You can't access another tenant's analytics.")
)
