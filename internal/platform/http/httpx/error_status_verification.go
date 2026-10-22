package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the verification error codes. As for MFA,
// an exhausted guess budget is 429, not a validation failure.
func init() {
	registerStatuses(map[string]int{
		errs.CodeVerifyAttemptsExceeded: http.StatusTooManyRequests,
	})
}
