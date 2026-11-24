package recovery

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrResetLinkInvalid = errs.New("recovery.reset_link_invalid", errs.KindInvalid, "This reset link is invalid.")
	ErrMagicLinkInvalid = errs.New("recovery.magic_link_invalid", errs.KindInvalid, "This sign-in link is invalid.")
	ErrLinkUsed         = errs.New("recovery.link_used", errs.KindInvalid, "This link has already been used. Request a new one.")
	ErrLinkExpired      = errs.New("recovery.link_expired", errs.KindInvalid, "This link has expired. Request a new one.")
)
