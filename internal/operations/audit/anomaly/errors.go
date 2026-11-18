package anomaly

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrAuditIDInvalid             = errs.New("audit.id_invalid", errs.KindInvalid, "That reference is invalid.")
	ErrAuditAnomalyStatusInvalid  = errs.New("audit.anomaly_status_invalid", errs.KindInvalid, `Choose a valid status: "open" or "resolved".`)
	ErrAuditScoreThresholdInvalid = errs.New("audit.score_threshold_invalid", errs.KindUnprocessable, "The score threshold must be between 0 and 1.")
	ErrAuditMinBaselineInvalid    = errs.New("audit.min_baseline_invalid", errs.KindUnprocessable, "The minimum baseline events must be 0 or greater.")
	ErrAuditResolveActorRequired  = errs.New("audit.resolve_actor_required", errs.KindUnauthenticated, "Resolving an anomaly must be attributed to a signed-in user.")
)
