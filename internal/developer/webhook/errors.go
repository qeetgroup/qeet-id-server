package webhook

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeURLNotAllowed = "webhook.url_not_allowed"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrDeliveryNotFound = errs.New("webhook.delivery_not_found", errs.KindNotFound, "That webhook delivery doesn't exist.")
	ErrURLRequired      = errs.New("webhook.url_required", errs.KindUnprocessable, "Enter a URL for the webhook.")
	ErrURLNotAllowed    = errs.New(CodeURLNotAllowed, errs.KindInvalid, "Webhooks can only be sent to a public https address, not a private, local or reserved one.")
	ErrInvalidID        = errs.New("webhook.invalid_id", errs.KindInvalid, "That identifier isn't valid.")
	ErrEventsRequired   = errs.New("webhook.events_required", errs.KindUnprocessable, "Choose at least one event for the webhook.")
	ErrEventUnknown     = errs.New("webhook.event_unknown", errs.KindUnprocessable, "That isn't an event a webhook can receive.")
	ErrNotFound         = errs.New("webhook.not_found", errs.KindNotFound, "That webhook subscription doesn't exist.")
)
