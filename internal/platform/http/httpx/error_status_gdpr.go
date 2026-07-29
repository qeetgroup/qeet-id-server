package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// GDPR (operations/gdpr) code→status mappings, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeGDPRFrameworkInvalid: http.StatusBadRequest,
		errs.CodeGDPRTenantInvalid:    http.StatusBadRequest,
		errs.CodeGDPRTenantMismatch:   http.StatusForbidden,
		errs.CodeGDPRIDInvalid:        http.StatusBadRequest,
	})
}
