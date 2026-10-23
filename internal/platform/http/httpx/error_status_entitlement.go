package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the plan-entitlement error codes. A locked
// feature and a reached limit are both 402: upgrading lets the request proceed,
// unlike a permanent 403.
func init() {
	registerStatuses(map[string]int{
		errs.CodeUpgradeRequired: http.StatusPaymentRequired,
		errs.CodePlanLimit:       http.StatusPaymentRequired,
	})
}
