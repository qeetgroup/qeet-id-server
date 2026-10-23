package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the Qeet AI error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeQeetAIUnconfigured:         http.StatusConflict,
		errs.CodeQeetAIProviderUnreachable:  http.StatusBadRequest,
		errs.CodeQeetAIProviderKeyInvalid:   http.StatusBadRequest,
		errs.CodeQeetAIProviderModelInvalid: http.StatusBadRequest,
		errs.CodeQeetAIProviderError:        http.StatusBadRequest,
	})
}
