package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Token-vault code→status mappings. Registered from init() so this bounded
// context owns its own statuses without editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeTokenVaultProviderNotFound:         http.StatusNotFound,
		errs.CodeTokenVaultProviderAuthorizeInvalid: http.StatusUnprocessableEntity,
		errs.CodeTokenVaultConnectStateInvalid:      http.StatusBadRequest,
		errs.CodeTokenVaultConnectExpired:           http.StatusBadRequest,
		errs.CodeTokenVaultTokenExchangeFailed:      http.StatusInternalServerError,
		errs.CodeTokenVaultGrantNotFound:            http.StatusNotFound,
		errs.CodeTokenVaultTokenExpired:             http.StatusUnauthorized,
		errs.CodeTokenVaultScopeRequired:            http.StatusForbidden,
	})
}
