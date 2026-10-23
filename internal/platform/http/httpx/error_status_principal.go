package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the service-principal error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodePrincipalNotFound:           http.StatusNotFound,
		errs.CodePrincipalInvalidCredentials: http.StatusUnauthorized,
		errs.CodePrincipalDisabled:           http.StatusUnauthorized,
		errs.CodePrincipalGrantUnsupported:   http.StatusBadRequest,
		errs.CodePrincipalInvalidID:          http.StatusBadRequest,
	})
}
