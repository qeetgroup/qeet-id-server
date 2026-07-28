package errs

// Webhook error codes — stable, namespaced machine identifiers for the
// internal/developer/webhooks domain. Clients branch and localize on these
// (never on the message text). Once shipped, a code MUST NOT change. Every
// identifier is prefixed with the `webhook` domain so it never collides with
// another bounded context.
const (
	CodeWebhookNotFound         = "webhook.not_found"
	CodeWebhookDeliveryNotFound = "webhook.delivery_not_found"
	CodeWebhookURLRequired      = "webhook.url_required"
	CodeWebhookInvalidID        = "webhook.invalid_id"
	CodeWebhookTenantMismatch   = "webhook.tenant_mismatch"
)

// Webhook errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrWebhookNotFound`, attaching a
// wrapped cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrWebhookNotFound         = New(CodeWebhookNotFound, "That webhook subscription doesn't exist.")
	ErrWebhookDeliveryNotFound = New(CodeWebhookDeliveryNotFound, "That webhook delivery doesn't exist.")
	ErrWebhookURLRequired      = New(CodeWebhookURLRequired, "Enter a URL for the webhook.")
	ErrWebhookInvalidID        = New(CodeWebhookInvalidID, "That identifier isn't valid.")
	ErrWebhookTenantMismatch   = New(CodeWebhookTenantMismatch, "You can only manage webhooks in your own tenant.")
)
