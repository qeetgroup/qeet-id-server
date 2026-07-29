package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Auth / credentials code→status mappings for the NEW auth codes added in
// errs/auth.go beyond the originals already mapped in the base error_status.go.
// Registered from init() so the auth domain owns its own transport mappings.
// Each status matches the generic sentinel the specific error replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthInvalidCredentials:       http.StatusUnauthorized,
		errs.CodeAuthAccountLocked:            http.StatusTooManyRequests,
		errs.CodeAuthNotTenantMember:          http.StatusForbidden,
		errs.CodeAuthSelfRegistrationDisabled: http.StatusForbidden,
		errs.CodeAuthPasswordWeak:             http.StatusUnprocessableEntity,
		errs.CodeAuthMFAChallengeExpired:      http.StatusUnauthorized,
		errs.CodeAuthRefreshTokenInvalid:      http.StatusUnauthorized,
		errs.CodeAuthSessionRevoked:           http.StatusUnauthorized,
		errs.CodeAuthAccountSuspended:         http.StatusUnauthorized,
	})
}
