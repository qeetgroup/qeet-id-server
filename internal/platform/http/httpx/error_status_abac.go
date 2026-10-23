package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the ABAC error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeABACNameRequired:         http.StatusUnprocessableEntity,
		errs.CodeABACEffectInvalid:        http.StatusUnprocessableEntity,
		errs.CodeABACResourceTypeRequired: http.StatusUnprocessableEntity,
		errs.CodeABACActionRequired:       http.StatusUnprocessableEntity,
		errs.CodeABACConditionInvalid:     http.StatusUnprocessableEntity,
		errs.CodeABACPolicyNameExists:     http.StatusConflict,
		errs.CodeABACPolicyLocksOut:       http.StatusConflict,
	})
}
