package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Email-template (operations/email) code→status mappings, registered from init().
func init() {
	registerStatuses(map[string]int{
		errs.CodeEmailTemplateNotFound:        http.StatusNotFound,
		errs.CodeEmailTemplateContentRequired: http.StatusUnprocessableEntity,
		errs.CodeEmailTenantInvalid:           http.StatusBadRequest,
		errs.CodeEmailTenantMismatch:          http.StatusForbidden,
	})
}
