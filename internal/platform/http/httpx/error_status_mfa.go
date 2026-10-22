package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the MFA error codes not in statusByCode.
func init() {
	registerStatuses(map[string]int{
		errs.CodeMFANotEnrolled:         http.StatusBadRequest,
		errs.CodeMFAFactorNotConfirmed:  http.StatusBadRequest,
		errs.CodeMFAAttemptsExceeded:    http.StatusTooManyRequests,
		errs.CodeMFAEnrollmentRequired:  http.StatusForbidden,
		errs.CodeMFACodeSendLimited:     http.StatusTooManyRequests,
		errs.CodeMFADeliveryUnavailable: http.StatusServiceUnavailable,
		errs.CodeMFADeliveryFailed:      http.StatusBadGateway,
		errs.CodeMFAFactorLimit:         http.StatusConflict,
		// Push MFA
		errs.CodeMFAPushDeviceNotFound:   http.StatusNotFound,
		errs.CodeMFAPushChallengeExpired: http.StatusGone,
		errs.CodeMFAPushChallengeInvalid: http.StatusConflict,
		errs.CodeMFAPushUnauthorized:     http.StatusUnauthorized,
		errs.CodeMFAPushPending:          http.StatusConflict,
		errs.CodeMFAPairingCodeInvalid:   http.StatusUnauthorized,
		errs.CodeMFAPushDeliveryFailed:   http.StatusBadGateway,
	})
}
