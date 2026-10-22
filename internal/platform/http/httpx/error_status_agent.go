package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the AI-agent error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAgentNotFound:          http.StatusNotFound,
		errs.CodeAgentStatusInvalid:     http.StatusBadRequest,
		errs.CodeAgentDecommissioned:    http.StatusConflict,
		errs.CodeAgentTransitionInvalid: http.StatusConflict,
		errs.CodeAgentNameRequired:      http.StatusUnprocessableEntity,
		errs.CodeAgentSponsorRequired:   http.StatusUnprocessableEntity,
		errs.CodeAgentSponsorNotMember:  http.StatusUnprocessableEntity,
		errs.CodeAgentTokenInvalid:      http.StatusUnauthorized,
		errs.CodeAgentInactive:          http.StatusUnauthorized,
		errs.CodeAgentInvalidID:         http.StatusBadRequest,
		errs.CodeAgentTenantMismatch:    http.StatusForbidden,
	})
}
