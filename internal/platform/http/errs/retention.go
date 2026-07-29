package errs

// Data-retention error codes — stable, namespaced machine identifiers for the
// operations/retention context (per-tenant retention policy + purge runs).
// Clients branch and localize on these codes, never on the message text.
const (
	CodeRetentionTenantInvalid  = "retention.tenant_invalid"
	CodeRetentionTenantMismatch = "retention.tenant_mismatch"
)

var (
	ErrRetentionTenantInvalid  = New(CodeRetentionTenantInvalid, "That tenant reference is invalid.")
	ErrRetentionTenantMismatch = New(CodeRetentionTenantMismatch, "You can't access another tenant's retention settings.")
)
