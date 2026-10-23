package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the authentication error codes not in statusByCode.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthRiskVerificationUnavailable: http.StatusForbidden,
		errs.CodeAuthInvalidCredentials:          http.StatusUnauthorized,
		errs.CodeAuthAccountLocked:               http.StatusTooManyRequests,
		errs.CodeAuthNotTenantMember:             http.StatusForbidden,
		errs.CodeAuthSelfRegistrationDisabled:    http.StatusForbidden,
		errs.CodeAuthMethodDisabled:              http.StatusForbidden,
		errs.CodeAuthApplicationToken:            http.StatusForbidden,
		errs.CodeAuthInsufficientScope:           http.StatusForbidden,
		errs.CodeAuthPasswordWeak:                http.StatusUnprocessableEntity,
		errs.CodeAuthMFAChallengeExpired:         http.StatusUnauthorized,
		errs.CodeAuthRefreshTokenInvalid:         http.StatusUnauthorized,
		errs.CodeAuthSessionRevoked:              http.StatusUnauthorized,
		errs.CodeAuthSessionTimedOut:             http.StatusUnauthorized,
		errs.CodeAuthLastSignInMethod:            http.StatusConflict,
		errs.CodeAuthSessionLimit:                http.StatusForbidden,
		errs.CodeAuthAccountSuspended:            http.StatusUnauthorized,
		errs.CodeAuthTenantInactive:              http.StatusForbidden,
		errs.CodeAuthSignInUnavailable:           http.StatusServiceUnavailable,
		errs.CodeAuthAddressNotAllowed:           http.StatusForbidden,
	})
}
