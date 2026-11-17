package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the SIEM log-sink error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSIEMSinkTypeInvalid:      http.StatusUnprocessableEntity,
		errs.CodeSIEMEndpointInvalid:      http.StatusUnprocessableEntity,
		errs.CodeSIEMOrganizationInvalid:  http.StatusBadRequest,
		errs.CodeSIEMOrganizationMismatch: http.StatusForbidden,
		errs.CodeSIEMIDInvalid:            http.StatusBadRequest,
	})
}
