package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the passkey error codes not in statusByCode.
func init() {
	registerStatuses(map[string]int{
		errs.CodePasskeyUserNotFound:       http.StatusNotFound,
		errs.CodePasskeySessionMismatch:    http.StatusBadRequest,
		errs.CodePasskeySessionInvalid:     http.StatusBadRequest,
		errs.CodePasskeyAttestationInvalid: http.StatusBadRequest,
		errs.CodePasskeyAssertionInvalid:   http.StatusBadRequest,
		errs.CodePasskeyNoCredentials:      http.StatusBadRequest,
		errs.CodePasskeyCloneDetected:      http.StatusUnauthorized,
		errs.CodePasskeyMFAFailed:          http.StatusUnauthorized,
		errs.CodePasskeyCeremonyFailed:     http.StatusBadRequest,
		errs.CodePasskeyDisabled:           http.StatusForbidden,
		errs.CodePasskeyBrowserMismatch:    http.StatusForbidden,
	})
}
