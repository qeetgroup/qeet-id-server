package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ReBAC code→status mappings. Registered from this bounded context's own file
// so the shared error_status.go stays free of per-domain entries. Statuses
// mirror the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeReBACObjectInvalid:           http.StatusUnprocessableEntity,
		errs.CodeReBACSubjectInvalid:          http.StatusUnprocessableEntity,
		errs.CodeReBACRelationRequired:        http.StatusUnprocessableEntity,
		errs.CodeReBACObjectSubjectExclusive:  http.StatusBadRequest,
		errs.CodeReBACObjectOrSubjectRequired: http.StatusBadRequest,
		errs.CodeReBACUserIDRelationRequired:  http.StatusUnprocessableEntity,
		errs.CodeReBACObjectRelationRequired:  http.StatusBadRequest,
	})
}
