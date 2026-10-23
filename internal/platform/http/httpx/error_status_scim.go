package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the SCIM error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSCIMTenantIDInvalid: http.StatusBadRequest,
		errs.CodeSCIMTenantMismatch:  http.StatusForbidden,
	})
}
