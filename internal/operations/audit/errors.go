package audit

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrCursorInvalid  = errs.New("audit.cursor_invalid", errs.KindInvalid, "That pagination cursor is invalid.")
	ErrActorIDInvalid = errs.New("audit.actor_id_invalid", errs.KindInvalid, "That actor reference is invalid.")
)
