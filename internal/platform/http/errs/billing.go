package errs

// Billing error codes: plans, subscriptions, checkout and provider webhooks.
const (
	CodeBillingCheckoutRequired = "billing.checkout_required"
)

// Billing errors. The Message is the end-user-facing text; edit wording here.
var (
	ErrBillingCheckoutRequired = New(CodeBillingCheckoutRequired, KindPaymentRequired, "This plan requires checkout. Start the paid signup flow to create this organization.")
)
