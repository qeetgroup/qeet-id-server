package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the data-retention error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeRetentionOrganizationInvalid:  http.StatusBadRequest,
		errs.CodeRetentionOrganizationMismatch: http.StatusForbidden,
	})
}
