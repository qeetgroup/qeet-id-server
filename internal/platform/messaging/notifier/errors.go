package notifier

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrEmailProviderUnavailable = errs.New("email.provider_unavailable", errs.KindUnavailable, "We couldn't send this message: no delivery provider is configured. Contact the administrator.")
)
