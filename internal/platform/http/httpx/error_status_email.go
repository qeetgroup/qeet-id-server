package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the email-template error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeEmailTemplateNotFound:        http.StatusNotFound,
		errs.CodeEmailTemplateContentRequired: http.StatusUnprocessableEntity,
		errs.CodeEmailTenantInvalid:           http.StatusBadRequest,
		errs.CodeEmailTenantMismatch:          http.StatusForbidden,
		errs.CodeEmailSuppressed:              http.StatusUnprocessableEntity,
		errs.CodeEmailProviderUnavailable:     http.StatusServiceUnavailable,
		errs.CodeEmailWebhookSignature:        http.StatusUnauthorized,
		errs.CodeEmailWebhookDisabled:         http.StatusNotFound,
	})
}
