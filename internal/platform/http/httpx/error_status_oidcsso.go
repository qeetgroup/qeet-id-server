package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the enterprise OIDC connection codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeOIDCSSOIDInvalid:               http.StatusBadRequest,
		errs.CodeOIDCSSOFieldsRequired:          http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOIssuerInvalid:           http.StatusUnprocessableEntity,
		errs.CodeOIDCSSODiscoveryURLInvalid:     http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOScopesInvalid:           http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOClaimInvalid:            http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOTenantIDsInvalid:        http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOTenantIDsRequired:       http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOStatusInvalid:           http.StatusUnprocessableEntity,
		errs.CodeOIDCSSOConnectionDraft:         http.StatusForbidden,
		errs.CodeOIDCSSOConnectionDisabled:      http.StatusForbidden,
		errs.CodeOIDCSSOMisconfigured:           http.StatusInternalServerError,
		errs.CodeOIDCSSOProviderUnreachable:     http.StatusBadGateway,
		errs.CodeOIDCSSOCallbackInvalid:         http.StatusBadRequest,
		errs.CodeOIDCSSOStateInvalid:            http.StatusBadRequest,
		errs.CodeOIDCSSOOtherBrowser:            http.StatusForbidden,
		errs.CodeOIDCSSOProviderRefused:         http.StatusUnauthorized,
		errs.CodeOIDCSSOTokenExchangeFailed:     http.StatusBadGateway,
		errs.CodeOIDCSSOIDTokenInvalid:          http.StatusUnauthorized,
		errs.CodeOIDCSSONoEmail:                 http.StatusBadRequest,
		errs.CodeOIDCSSOEmailUnverified:         http.StatusForbidden,
		errs.CodeOIDCSSOEmailDomainUnverified:   http.StatusForbidden,
		errs.CodeOIDCSSOUserTenantMismatch:      http.StatusForbidden,
		errs.CodeOIDCSSOAccountUnverified:       http.StatusForbidden,
		errs.CodeOIDCSSOAccountAdministers:      http.StatusForbidden,
		errs.CodeOIDCSSOJITNotAllowed:           http.StatusForbidden,
		errs.CodeOIDCSSOLoginCodeRequired:       http.StatusBadRequest,
		errs.CodeOIDCSSOLoginCodeInvalid:        http.StatusUnauthorized,
		errs.CodeOIDCSSOLoginCodeUsed:           http.StatusUnauthorized,
		errs.CodeOIDCSSOLoginCodeExpired:        http.StatusUnauthorized,
		errs.CodeOIDCSSOSecretEncryptionMissing: http.StatusInternalServerError,
	})
}
