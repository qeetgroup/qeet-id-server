package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// init registers the HTTP statuses of the webhook error codes.
func init() {
	registerStatuses(map[string]int{
		errs.CodeWebhookNotFound:         http.StatusNotFound,
		errs.CodeWebhookDeliveryNotFound: http.StatusNotFound,
		errs.CodeWebhookURLRequired:      http.StatusUnprocessableEntity,
		errs.CodeWebhookInvalidID:        http.StatusBadRequest,
		errs.CodeWebhookTenantMismatch:   http.StatusForbidden,
		errs.CodeWebhookEventsRequired:   http.StatusUnprocessableEntity,
		errs.CodeWebhookEventUnknown:     http.StatusUnprocessableEntity,
	})
}
