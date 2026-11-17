package errs

// Analytics error codes.
const (
	CodeAnalyticsOrganizationInvalid  = "analytics.tenant_invalid"
	CodeAnalyticsOrganizationMismatch = "analytics.tenant_mismatch"
)

var (
	ErrAnalyticsOrganizationInvalid  = New(CodeAnalyticsOrganizationInvalid, "That tenant reference is invalid.")
	ErrAnalyticsOrganizationMismatch = New(CodeAnalyticsOrganizationMismatch, "You can't access another tenant's analytics.")
)
