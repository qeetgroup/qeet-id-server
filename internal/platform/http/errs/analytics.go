package errs

// Analytics error codes — stable, namespaced machine identifiers for the
// operations/analytics context (per-tenant analytics overview). Clients branch
// and localize on these codes, never on the message text.
const (
	CodeAnalyticsTenantInvalid  = "analytics.tenant_invalid"
	CodeAnalyticsTenantMismatch = "analytics.tenant_mismatch"
)

var (
	ErrAnalyticsTenantInvalid  = New(CodeAnalyticsTenantInvalid, "That tenant reference is invalid.")
	ErrAnalyticsTenantMismatch = New(CodeAnalyticsTenantMismatch, "You can't access another tenant's analytics.")
)
