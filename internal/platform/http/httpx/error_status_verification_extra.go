package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the verification start-flow error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeVerifyUserNotFound: http.StatusNotFound,
		errs.CodeVerifyNoEmail:      http.StatusUnprocessableEntity,
		errs.CodeVerifyNoPhone:      http.StatusUnprocessableEntity,
	})
}
