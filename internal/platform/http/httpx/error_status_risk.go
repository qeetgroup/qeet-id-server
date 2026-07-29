package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Risk (adaptive-access) code→status mappings. Registered from init() so the
// risk bounded context owns its own transport mapping without editing the base
// error_status.go table.
func init() {
	registerStatuses(map[string]int{
		errs.CodeRiskCIDRInvalid: http.StatusUnprocessableEntity,
	})
}
