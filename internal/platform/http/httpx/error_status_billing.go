package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Billing (operations/billing) code→status mappings. Registered from init() so
// the billing context owns its own transport mappings without editing the
// shared error_status.go.
func init() {
	registerStatuses(map[string]int{
		errs.CodeBillingPlanNotFound:              http.StatusNotFound,
		errs.CodeBillingNoActiveSubscription:      http.StatusNotFound,
		errs.CodeBillingCurrencyInvalid:           http.StatusUnprocessableEntity,
		errs.CodeBillingCountryInvalid:            http.StatusUnprocessableEntity,
		errs.CodeBillingPlanNotPriced:             http.StatusUnprocessableEntity,
		errs.CodeBillingCheckoutURLInvalid:        http.StatusUnprocessableEntity,
		errs.CodeBillingReturnURLInvalid:          http.StatusBadRequest,
		errs.CodeBillingCheckoutRefInvalid:        http.StatusBadRequest,
		errs.CodeBillingProviderUnknown:           http.StatusNotFound,
		errs.CodeBillingWebhookVerificationFailed: http.StatusUnauthorized,
		errs.CodeBillingTenantInvalid:             http.StatusBadRequest,
		errs.CodeBillingTenantMismatch:            http.StatusForbidden,
		errs.CodeBillingCheckoutRequired:          http.StatusPaymentRequired,
	})
}
