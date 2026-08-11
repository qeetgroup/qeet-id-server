package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// MFA code→status mappings for the NEW mfa codes added in errs/mfa.go beyond the
// originals already mapped in the base error_status.go. Registered from init()
// so the mfa domain owns its own transport mappings. Each status matches the
// generic sentinel the specific error replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeMFANotEnrolled:        http.StatusBadRequest,
		errs.CodeMFAFactorNotConfirmed: http.StatusBadRequest,
		// Push MFA
		errs.CodeMFAPushDeviceNotFound:   http.StatusNotFound,
		errs.CodeMFAPushChallengeExpired: http.StatusGone,
		errs.CodeMFAPushChallengeInvalid: http.StatusConflict,
		errs.CodeMFAPushUnauthorized:     http.StatusUnauthorized,
	})
}
