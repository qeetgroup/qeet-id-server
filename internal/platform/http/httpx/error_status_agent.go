package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Agent (internal/developer/agents) code→status mappings. Registered from an
// init() so this bounded context owns its own transport mappings without
// editing the shared error_status.go.
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
