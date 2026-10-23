package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the ReBAC error codes.
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
