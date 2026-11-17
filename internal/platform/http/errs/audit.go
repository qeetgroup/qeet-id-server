package errs

// Audit log and anomaly detection error codes.
const (
	CodeAuditCursorInvalid         = "audit.cursor_invalid"
	CodeAuditOrganizationInvalid   = "audit.tenant_invalid"
	CodeAuditOrganizationMismatch  = "audit.tenant_mismatch"
	CodeAuditActorIDInvalid        = "audit.actor_id_invalid"
	CodeAuditIDInvalid             = "audit.id_invalid"
	CodeAuditAnomalyStatusInvalid  = "audit.anomaly_status_invalid"
	CodeAuditScoreThresholdInvalid = "audit.score_threshold_invalid"
	CodeAuditMinBaselineInvalid    = "audit.min_baseline_invalid"
	CodeAuditResolveActorRequired  = "audit.resolve_actor_required"
)

var (
	ErrAuditCursorInvalid         = New(CodeAuditCursorInvalid, "That pagination cursor is invalid.")
	ErrAuditOrganizationInvalid   = New(CodeAuditOrganizationInvalid, "That tenant reference is invalid.")
	ErrAuditOrganizationMismatch  = New(CodeAuditOrganizationMismatch, "You can't access another tenant's audit data.")
	ErrAuditActorIDInvalid        = New(CodeAuditActorIDInvalid, "That actor reference is invalid.")
	ErrAuditIDInvalid             = New(CodeAuditIDInvalid, "That reference is invalid.")
	ErrAuditAnomalyStatusInvalid  = New(CodeAuditAnomalyStatusInvalid, `Choose a valid status: "open" or "resolved".`)
	ErrAuditScoreThresholdInvalid = New(CodeAuditScoreThresholdInvalid, "The score threshold must be between 0 and 1.")
	ErrAuditMinBaselineInvalid    = New(CodeAuditMinBaselineInvalid, "The minimum baseline events must be 0 or greater.")
	ErrAuditResolveActorRequired  = New(CodeAuditResolveActorRequired, "Resolving an anomaly must be attributed to a signed-in user.")
)
