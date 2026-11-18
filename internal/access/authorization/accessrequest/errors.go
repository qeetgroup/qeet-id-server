package accessrequest

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrRoleHeld   = errs.New("access_request.role_held", errs.KindConflict, "You already have this role.")
	ErrPending    = errs.New("access_request.pending", errs.KindConflict, "You've already asked for this role. Wait for an answer, or cancel that request.")
	ErrClosed     = errs.New("access_request.closed", errs.KindConflict, "This request has already been answered, cancelled or has expired.")
	ErrOwn        = errs.New("access_request.own", errs.KindForbidden, "Someone else has to answer your own request.")
	ErrNoteNeeded = errs.New("access_request.note_required", errs.KindUnprocessable, "Say why you're denying it. They'll see your reason.")
)
