package invite

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrInvalid       = errs.New("invite.invalid", errs.KindInvalid, "This invitation is no longer valid.")
	ErrExpired       = errs.New("invite.expired", errs.KindInvalid, "This invitation has expired. Ask for a new one.")
	ErrEmailMismatch = errs.New("invite.email_mismatch", errs.KindForbidden, "This invitation was sent to a different email address.")
	ErrRoleRequired  = errs.New("invite.role_required", errs.KindUnprocessable, "This person belongs to another organization, so the invitation needs a role to give them here.")
)
