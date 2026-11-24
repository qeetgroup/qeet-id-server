package billing

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrPlanNotFound              = errs.New("billing.plan_not_found", errs.KindNotFound, "That billing plan doesn't exist.")
	ErrNoActiveSubscription      = errs.New("billing.no_active_subscription", errs.KindNotFound, "There's no active subscription to change.")
	ErrCurrencyInvalid           = errs.New("billing.currency_invalid", errs.KindUnprocessable, "Enter a valid 3-letter currency code.")
	ErrCountryInvalid            = errs.New("billing.country_invalid", errs.KindUnprocessable, "Enter a valid 2-letter country code.")
	ErrPlanNotPriced             = errs.New("billing.plan_not_priced", errs.KindUnprocessable, "That plan isn't available in the selected currency.")
	ErrCheckoutURLInvalid        = errs.New("billing.checkout_url_invalid", errs.KindUnprocessable, "Provide valid success and cancel URLs.")
	ErrReturnURLInvalid          = errs.New("billing.return_url_invalid", errs.KindInvalid, "The return URL is invalid.")
	ErrCheckoutRefInvalid        = errs.New("billing.checkout_ref_invalid", errs.KindInvalid, "That checkout reference is invalid.")
	ErrProviderUnknown           = errs.New("billing.provider_unknown", errs.KindNotFound, "That payment provider isn't configured.")
	ErrWebhookVerificationFailed = errs.New("billing.webhook_verification_failed", errs.KindUnauthenticated, "We couldn't verify this webhook request.")
	ErrTaxIDInvalid              = errs.New("billing.tax_id_invalid", errs.KindUnprocessable, "That tax ID isn't valid.")
	ErrTrialNotEligible          = errs.New("billing.trial_not_eligible", errs.KindConflict, "This organization isn't eligible for a trial.")
	ErrInvoiceNotOpen            = errs.New("billing.invoice_not_open", errs.KindConflict, "This invoice isn't open: it's already paid, or no longer owed.")
	ErrInvoiceNotFound           = errs.New("billing.invoice_not_found", errs.KindNotFound, "That invoice doesn't exist.")
)
