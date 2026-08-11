package errs

// Billing / subscription / checkout error codes — stable, namespaced machine
// identifiers for the operations/billing context (plans, subscriptions, hosted
// checkout, provider webhooks). Clients branch and localize on these codes,
// never on the message text.
const (
	CodeBillingPlanNotFound              = "billing.plan_not_found"
	CodeBillingNoActiveSubscription      = "billing.no_active_subscription"
	CodeBillingCurrencyInvalid           = "billing.currency_invalid"
	CodeBillingCountryInvalid            = "billing.country_invalid"
	CodeBillingPlanNotPriced             = "billing.plan_not_priced"
	CodeBillingCheckoutURLInvalid        = "billing.checkout_url_invalid"
	CodeBillingReturnURLInvalid          = "billing.return_url_invalid"
	CodeBillingCheckoutRefInvalid        = "billing.checkout_ref_invalid"
	CodeBillingProviderUnknown           = "billing.provider_unknown"
	CodeBillingWebhookVerificationFailed = "billing.webhook_verification_failed"
	CodeBillingTenantInvalid             = "billing.tenant_invalid"
	CodeBillingTenantMismatch            = "billing.tenant_mismatch"
	CodeBillingCheckoutRequired          = "billing.checkout_required"
	CodeBillingTaxIDInvalid              = "billing.tax_id_invalid"
	CodeBillingTrialNotEligible          = "billing.trial_not_eligible"
)

// Billing errors. The Message is the end-user-facing text; edit wording here.
var (
	ErrBillingPlanNotFound              = New(CodeBillingPlanNotFound, "That billing plan doesn't exist.")
	ErrBillingNoActiveSubscription      = New(CodeBillingNoActiveSubscription, "There's no active subscription to change.")
	ErrBillingCurrencyInvalid           = New(CodeBillingCurrencyInvalid, "Enter a valid 3-letter currency code.")
	ErrBillingCountryInvalid            = New(CodeBillingCountryInvalid, "Enter a valid 2-letter country code.")
	ErrBillingPlanNotPriced             = New(CodeBillingPlanNotPriced, "That plan isn't available in the selected currency.")
	ErrBillingCheckoutURLInvalid        = New(CodeBillingCheckoutURLInvalid, "Provide valid success and cancel URLs.")
	ErrBillingReturnURLInvalid          = New(CodeBillingReturnURLInvalid, "The return URL is invalid.")
	ErrBillingCheckoutRefInvalid        = New(CodeBillingCheckoutRefInvalid, "That checkout reference is invalid.")
	ErrBillingProviderUnknown           = New(CodeBillingProviderUnknown, "That payment provider isn't configured.")
	ErrBillingWebhookVerificationFailed = New(CodeBillingWebhookVerificationFailed, "We couldn't verify this webhook request.")
	ErrBillingTenantInvalid             = New(CodeBillingTenantInvalid, "That tenant reference is invalid.")
	ErrBillingTenantMismatch            = New(CodeBillingTenantMismatch, "You can't access another tenant's billing.")
	// ErrBillingCheckoutRequired: a paid plan can't be self-provisioned free via
	// POST /v1/tenants — it must go through the signup checkout so payment is
	// captured before the org exists.
	ErrBillingCheckoutRequired = New(CodeBillingCheckoutRequired, "This plan requires checkout. Start the paid signup flow to create this organization.")
	ErrBillingTaxIDInvalid     = New(CodeBillingTaxIDInvalid, "That tax ID isn't valid.")
	ErrBillingTrialNotEligible = New(CodeBillingTrialNotEligible, "This organization isn't eligible for a trial.")
)
