package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the auth-policy error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAuthPolicyPasswordTooShort:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoUppercase: http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoNumber:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordNoSymbol:    http.StatusUnprocessableEntity,
		errs.CodeAuthPolicyPasswordBreached:    http.StatusUnprocessableEntity,
	})
}
