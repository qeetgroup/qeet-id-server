package errs

// GDPR / compliance error codes — stable, namespaced machine identifiers for
// the operations/gdpr context (data-subject requests, exports, and compliance
// evidence runs). Clients branch and localize on these codes, not the message.
const (
	CodeGDPRFrameworkInvalid = "gdpr.framework_invalid"
	CodeGDPRTenantInvalid    = "gdpr.tenant_invalid"
	CodeGDPRTenantMismatch   = "gdpr.tenant_mismatch"
	CodeGDPRIDInvalid        = "gdpr.id_invalid"
)

var (
	ErrGDPRFrameworkInvalid = New(CodeGDPRFrameworkInvalid, "Choose a supported framework: soc2 or iso27001.")
	ErrGDPRTenantInvalid    = New(CodeGDPRTenantInvalid, "That tenant reference is invalid.")
	ErrGDPRTenantMismatch   = New(CodeGDPRTenantMismatch, "You can't access another tenant's compliance data.")
	ErrGDPRIDInvalid        = New(CodeGDPRIDInvalid, "That reference is invalid.")
)
