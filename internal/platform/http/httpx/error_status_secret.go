package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Secret-vault code→status mappings. Registered from init() so this bounded
// context owns its own statuses without editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSecretNotFound:          http.StatusNotFound,
		errs.CodeSecretNameValueRequired: http.StatusUnprocessableEntity,
		errs.CodeSecretNameExists:        http.StatusConflict,
		errs.CodeSecretValueRequired:     http.StatusUnprocessableEntity,
		errs.CodeSecretDecryptFailed:     http.StatusInternalServerError,
		errs.CodeSecretScopeRequired:     http.StatusForbidden,
	})
}
