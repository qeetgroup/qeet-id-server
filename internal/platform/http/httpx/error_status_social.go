package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Social-login code→status mappings. Registered from this bounded context's own
// file so the shared error_status.go stays free of per-domain entries. Statuses
// mirror the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeSocialTenantRequired:        http.StatusBadRequest,
		errs.CodeSocialTenantNotFound:        http.StatusNotFound,
		errs.CodeSocialProviderNotConfigured: http.StatusNotFound,
		errs.CodeSocialProviderDisabled:      http.StatusBadRequest,
		errs.CodeSocialProviderNoDiscovery:   http.StatusBadRequest,
		errs.CodeSocialDiscoveryFailed:       http.StatusUnprocessableEntity,
		errs.CodeSocialCallbackParamsMissing: http.StatusBadRequest,
		errs.CodeSocialStateInvalid:          http.StatusBadRequest,
		errs.CodeSocialProviderMismatch:      http.StatusBadRequest,
		errs.CodeSocialStateExpired:          http.StatusBadRequest,
		errs.CodeSocialTokenExchangeFailed:   http.StatusUnprocessableEntity,
		errs.CodeSocialUserinfoFailed:        http.StatusUnprocessableEntity,
		errs.CodeSocialEmailMissing:          http.StatusBadRequest,
		errs.CodeSocialCodeRequired:          http.StatusBadRequest,
		errs.CodeSocialLoginCodeInvalid:      http.StatusUnauthorized,
		errs.CodeSocialLoginCodeUsed:         http.StatusUnauthorized,
		errs.CodeSocialLoginCodeExpired:      http.StatusUnauthorized,
		errs.CodeSocialAlreadyLinked:         http.StatusConflict,
		errs.CodeSocialNoAccount:             http.StatusNotFound,
	})
}
