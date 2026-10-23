package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the GDPR error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeGDPRFrameworkInvalid: http.StatusBadRequest,
		errs.CodeGDPRTenantInvalid:    http.StatusBadRequest,
		errs.CodeGDPRTenantMismatch:   http.StatusForbidden,
		errs.CodeGDPRIDInvalid:        http.StatusBadRequest,
	})
}
