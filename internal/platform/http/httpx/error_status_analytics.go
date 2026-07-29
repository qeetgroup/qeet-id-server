package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Analytics (operations/analytics) code→status mappings, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeAnalyticsTenantInvalid:  http.StatusBadRequest,
		errs.CodeAnalyticsTenantMismatch: http.StatusForbidden,
	})
}
