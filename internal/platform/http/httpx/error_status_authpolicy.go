package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Auth-policy code→status mappings. Registered from this bounded context's own
// file so the shared error_status.go stays free of per-domain entries.
// Statuses mirror the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthPolicyPasswordTooShort:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoUppercase: http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoNumber:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoSymbol:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordBreached:    http.StatusUnprocessableEntity,
	})
}
