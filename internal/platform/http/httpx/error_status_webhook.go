package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Webhook (internal/developer/webhooks) code→status mappings. Registered from
// an init() so this bounded context owns its own transport mappings without
// editing the shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeWebhookNotFound:         http.StatusNotFound,
		errs.CodeWebhookDeliveryNotFound: http.StatusNotFound,
		errs.CodeWebhookURLRequired:      http.StatusUnprocessableEntity,
		errs.CodeWebhookInvalidID:        http.StatusBadRequest,
		errs.CodeWebhookTenantMismatch:   http.StatusForbidden,
	})
}
