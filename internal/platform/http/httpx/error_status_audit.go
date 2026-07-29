package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Audit-log & anomaly (operations/audit + operations/audit/anomaly) code→status
// mappings for the shared `audit` domain, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuditCursorInvalid:         http.StatusBadRequest,
		errs.CodeAuditTenantInvalid:         http.StatusBadRequest,
		errs.CodeAuditTenantMismatch:        http.StatusForbidden,
		errs.CodeAuditActorIDInvalid:        http.StatusBadRequest,
		errs.CodeAuditIDInvalid:             http.StatusBadRequest,
		errs.CodeAuditAnomalyStatusInvalid:  http.StatusBadRequest,
		errs.CodeAuditScoreThresholdInvalid: http.StatusUnprocessableEntity,
		errs.CodeAuditMinBaselineInvalid:    http.StatusUnprocessableEntity,
		errs.CodeAuditResolveActorRequired:  http.StatusUnauthorized,
	})
}
