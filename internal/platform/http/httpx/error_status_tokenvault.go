package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the token-vault error codes.
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
		errs.CodeTokenVaultPeopleOnly:               http.StatusForbidden,
	})
}
