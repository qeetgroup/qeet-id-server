package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Plan-entitlement code→status mappings. Both a locked feature and a reached
// limit surface as 402 Payment Required (already used for checkout_required),
// signalling "pay/upgrade to proceed" rather than a permanent 403.
func init() {
	registerStatuses(map[string]int{
		errs.CodeUpgradeRequired: http.StatusPaymentRequired,
		errs.CodePlanLimit:       http.StatusPaymentRequired,
	})
}
