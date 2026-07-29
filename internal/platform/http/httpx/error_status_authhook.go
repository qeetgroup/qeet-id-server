package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Auth-hook (internal/developer/auth-hooks) code→status mappings. Registered
// from an init() so this bounded context owns its own transport mappings
// without editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthHookNotFound:       http.StatusNotFound,
		errs.CodeAuthHookDenied:         http.StatusForbidden,
		errs.CodeAuthHookURLInvalid:     http.StatusUnprocessableEntity,
		errs.CodeAuthHookInvalidID:      http.StatusBadRequest,
		errs.CodeAuthHookTenantMismatch: http.StatusForbidden,
	})
}
