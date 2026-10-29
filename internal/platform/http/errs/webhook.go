package errs

// Webhook error codes.
const (
	CodeWebhookNotFound         = "webhook.not_found"
	CodeWebhookDeliveryNotFound = "webhook.delivery_not_found"
	CodeWebhookURLRequired      = "webhook.url_required"
	CodeWebhookInvalidID        = "webhook.invalid_id"
	CodeWebhookTenantMismatch   = "webhook.tenant_mismatch"
	CodeWebhookEventsRequired   = "webhook.events_required"
	CodeWebhookEventUnknown     = "webhook.event_unknown"
	CodeWebhookURLNotAllowed    = "webhook.url_not_allowed"
)

// Webhook errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrWebhookNotFound`, attaching a
// wrapped cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrWebhookNotFound         = New(CodeWebhookNotFound, "That webhook subscription doesn't exist.")
	ErrWebhookDeliveryNotFound = New(CodeWebhookDeliveryNotFound, "That webhook delivery doesn't exist.")
	ErrWebhookURLRequired      = New(CodeWebhookURLRequired, "Enter a URL for the webhook.")
	ErrWebhookURLNotAllowed    = New(CodeWebhookURLNotAllowed,
		"Webhooks can only be sent to a public https address, not a private, local or reserved one.")
	ErrWebhookInvalidID      = New(CodeWebhookInvalidID, "That identifier isn't valid.")
	ErrWebhookTenantMismatch = New(CodeWebhookTenantMismatch, "You can only manage webhooks in your own tenant.")
	ErrWebhookEventsRequired = New(CodeWebhookEventsRequired, "Choose at least one event for the webhook.")
	ErrWebhookEventUnknown   = New(CodeWebhookEventUnknown, "That isn't an event a webhook can receive.")
)
