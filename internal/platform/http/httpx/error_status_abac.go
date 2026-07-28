package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// ABAC code→status mappings. Registered from this bounded context's own file so
// the shared error_status.go stays free of per-domain entries. Statuses mirror
// the generic sentinels these codes replaced.
func init() {
	registerStatuses(map[string]int{
		errs.CodeABACNameRequired:         http.StatusUnprocessableEntity,
		errs.CodeABACEffectInvalid:        http.StatusUnprocessableEntity,
		errs.CodeABACResourceTypeRequired: http.StatusUnprocessableEntity,
		errs.CodeABACActionRequired:       http.StatusUnprocessableEntity,
		errs.CodeABACConditionInvalid:     http.StatusUnprocessableEntity,
		errs.CodeABACPolicyNameExists:     http.StatusConflict,
	})
}
