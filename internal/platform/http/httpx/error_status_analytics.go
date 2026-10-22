package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the analytics error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAnalyticsTenantInvalid:  http.StatusBadRequest,
		errs.CodeAnalyticsTenantMismatch: http.StatusForbidden,
	})
}
