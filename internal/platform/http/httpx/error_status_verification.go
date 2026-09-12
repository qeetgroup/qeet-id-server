package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Verification code→status mappings registered from the verification domain,
// mirroring the pattern in error_status_auth.go. Matches the MFA equivalent:
// an exhausted guess budget is 429, not a validation failure.
func init() {
	registerStatuses(map[string]int{
		errs.CodeVerifyAttemptsExceeded: http.StatusTooManyRequests,
	})
}
