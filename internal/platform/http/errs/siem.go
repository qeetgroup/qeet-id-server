package errs

// SIEM log sink error codes.
const (
	CodeSIEMSinkTypeInvalid = "siem.sink_type_invalid"
	CodeSIEMEndpointInvalid = "siem.endpoint_invalid"
	CodeSIEMTenantInvalid   = "siem.tenant_invalid"
	CodeSIEMTenantMismatch  = "siem.tenant_mismatch"
	CodeSIEMIDInvalid       = "siem.id_invalid"
)

var (
	ErrSIEMSinkTypeInvalid = New(CodeSIEMSinkTypeInvalid, "Choose a supported sink type: splunk_hec, datadog, or http.")
	ErrSIEMEndpointInvalid = New(CodeSIEMEndpointInvalid, "Enter an absolute http(s) endpoint URL.")
	ErrSIEMTenantInvalid   = New(CodeSIEMTenantInvalid, "That tenant reference is invalid.")
	ErrSIEMTenantMismatch  = New(CodeSIEMTenantMismatch, "You can't access another tenant's log sinks.")
	ErrSIEMIDInvalid       = New(CodeSIEMIDInvalid, "That reference is invalid.")
)
