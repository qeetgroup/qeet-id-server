package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Service-principal (internal/developer/principal) code→status mappings.
// Registered from an init() so this bounded context owns its own transport
// mappings without editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodePrincipalNotFound:           http.StatusNotFound,
		errs.CodePrincipalInvalidCredentials: http.StatusUnauthorized,
		errs.CodePrincipalDisabled:           http.StatusUnauthorized,
		errs.CodePrincipalGrantUnsupported:   http.StatusBadRequest,
		errs.CodePrincipalInvalidID:          http.StatusBadRequest,
	})
}
