package delivery

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrEmailWebhookSignature = errs.New("email.webhook_signature_invalid", errs.KindUnauthenticated, "The notification's signature could not be verified.")
	ErrEmailWebhookDisabled  = errs.New("email.webhook_disabled", errs.KindNotFound, "Email notifications are not received here.")
)
