package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the auth-hook error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthHookNotFound:       http.StatusNotFound,
		errs.CodeAuthHookDenied:         http.StatusForbidden,
		errs.CodeAuthHookURLInvalid:     http.StatusUnprocessableEntity,
		errs.CodeAuthHookInvalidID:      http.StatusBadRequest,
		errs.CodeAuthHookTenantMismatch: http.StatusForbidden,
	})
}
