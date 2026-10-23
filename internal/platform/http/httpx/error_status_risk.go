package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the adaptive-risk error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeRiskCIDRInvalid:        http.StatusUnprocessableEntity,
		errs.CodeRiskRuleActionInvalid:  http.StatusUnprocessableEntity,
		errs.CodeRiskRulesLockOutCaller: http.StatusConflict,
	})
}
