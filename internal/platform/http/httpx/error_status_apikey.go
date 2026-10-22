package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the API-key error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeAPIKeyNotFound:     http.StatusNotFound,
		errs.CodeAPIKeyInvalid:      http.StatusUnauthorized,
		errs.CodeAPIKeyExpired:      http.StatusUnauthorized,
		errs.CodeAPIKeyNameRequired: http.StatusUnprocessableEntity,
		errs.CodeAPIKeyUserNotSelf:  http.StatusForbidden,
		errs.CodeAPIKeyInvalidID:    http.StatusBadRequest,
	})
}
