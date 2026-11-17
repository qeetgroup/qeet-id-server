package errs

// GDPR error codes: data-subject requests, exports and compliance evidence.
const (
	CodeGDPRFrameworkInvalid     = "gdpr.framework_invalid"
	CodeGDPROrganizationInvalid  = "gdpr.tenant_invalid"
	CodeGDPROrganizationMismatch = "gdpr.tenant_mismatch"
	CodeGDPRIDInvalid            = "gdpr.id_invalid"
)

var (
	ErrGDPRFrameworkInvalid     = New(CodeGDPRFrameworkInvalid, "Choose a supported framework: soc2 or iso27001.")
	ErrGDPROrganizationInvalid  = New(CodeGDPROrganizationInvalid, "That tenant reference is invalid.")
	ErrGDPROrganizationMismatch = New(CodeGDPROrganizationMismatch, "You can't access another tenant's compliance data.")
	ErrGDPRIDInvalid            = New(CodeGDPRIDInvalid, "That reference is invalid.")
)
