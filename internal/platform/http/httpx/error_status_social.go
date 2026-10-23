package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the social-login error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSocialTenantRequired:        http.StatusBadRequest,
		errs.CodeSocialTenantNotFound:        http.StatusNotFound,
		errs.CodeSocialProviderNotConfigured: http.StatusNotFound,
		errs.CodeSocialProviderDisabled:      http.StatusBadRequest,
		errs.CodeSocialProviderInUse:         http.StatusConflict,
		errs.CodeSocialProviderNoDiscovery:   http.StatusBadRequest,
		errs.CodeSocialDiscoveryFailed:       http.StatusUnprocessableEntity,
		errs.CodeSocialCallbackParamsMissing: http.StatusBadRequest,
		errs.CodeSocialStateInvalid:          http.StatusBadRequest,
		errs.CodeSocialProviderMismatch:      http.StatusBadRequest,
		errs.CodeSocialStateExpired:          http.StatusBadRequest,
		errs.CodeSocialTokenExchangeFailed:   http.StatusUnprocessableEntity,
		errs.CodeSocialUserinfoFailed:        http.StatusUnprocessableEntity,
		errs.CodeSocialEmailMissing:          http.StatusBadRequest,
		errs.CodeSocialReturnToInvalid:       http.StatusBadRequest,
		errs.CodeSocialAccountNotInTenant:    http.StatusForbidden,
		errs.CodeSocialEmailUnverified:       http.StatusForbidden,
		errs.CodeSocialAccountUnverified:     http.StatusForbidden,
		errs.CodeSocialCodeRequired:          http.StatusBadRequest,
		errs.CodeSocialLoginCodeInvalid:      http.StatusUnauthorized,
		errs.CodeSocialLoginCodeUsed:         http.StatusUnauthorized,
		errs.CodeSocialLoginCodeExpired:      http.StatusUnauthorized,
		errs.CodeSocialAlreadyLinked:         http.StatusConflict,
		errs.CodeSocialNoAccount:             http.StatusNotFound,
		errs.CodeSocialBrowserMismatch:       http.StatusForbidden,
		errs.CodeSocialLinkCodeInvalid:       http.StatusBadRequest,
		errs.CodeSocialLinkAccountMismatch:   http.StatusForbidden,
	})
}
