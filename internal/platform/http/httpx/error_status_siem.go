package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// SIEM / log-sink (operations/siem) code→status mappings, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeSIEMSinkTypeInvalid: http.StatusUnprocessableEntity,
		errs.CodeSIEMEndpointInvalid: http.StatusUnprocessableEntity,
		errs.CodeSIEMTenantInvalid:   http.StatusBadRequest,
		errs.CodeSIEMTenantMismatch:  http.StatusForbidden,
		errs.CodeSIEMIDInvalid:       http.StatusBadRequest,
	})
}
