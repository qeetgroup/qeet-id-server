package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Data-retention (operations/retention) code→status mappings, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeRetentionTenantInvalid:  http.StatusBadRequest,
		errs.CodeRetentionTenantMismatch: http.StatusForbidden,
	})
}
