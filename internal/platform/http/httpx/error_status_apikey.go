package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// API-key (internal/developer/api-keys) code→status mappings. Registered from
// an init() so this bounded context owns its own transport mappings without
// editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAPIKeyNotFound:     http.StatusNotFound,
		errs.CodeAPIKeyInvalid:      http.StatusUnauthorized,
		errs.CodeAPIKeyExpired:      http.StatusUnauthorized,
		errs.CodeAPIKeyNameRequired: http.StatusUnprocessableEntity,
		errs.CodeAPIKeyInvalidID:    http.StatusBadRequest,
	})
}
