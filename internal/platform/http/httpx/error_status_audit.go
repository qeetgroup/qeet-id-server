package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the audit-log and anomaly error codes.
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
