package authhook

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrNotFound   = errs.New("authhook.not_found", errs.KindNotFound, "That auth hook doesn't exist.")
	ErrURLInvalid = errs.New("authhook.url_invalid", errs.KindUnprocessable, "Enter an absolute http(s) URL for the auth hook.")
	ErrInvalidID  = errs.New("authhook.invalid_id", errs.KindInvalid, "That identifier isn't valid.")
)
