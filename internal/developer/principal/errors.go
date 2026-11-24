package principal

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrNotFound  = errs.New("principal.not_found", errs.KindNotFound, "That service principal doesn't exist.")
	ErrInvalidID = errs.New("principal.invalid_id", errs.KindInvalid, "That identifier isn't valid.")
)
