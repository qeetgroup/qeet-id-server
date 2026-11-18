package agent

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrStatusInvalid     = errs.New("agent.status_invalid", errs.KindInvalid, "That agent status isn't valid.")
	ErrDecommissioned    = errs.New("agent.decommissioned", errs.KindConflict, "This agent has been decommissioned and can no longer be changed.")
	ErrTransitionInvalid = errs.New("agent.transition_invalid", errs.KindConflict, "This agent can't move to that status.")
	ErrNameRequired      = errs.New("agent.name_required", errs.KindUnprocessable, "Enter a name for the agent.")
	ErrSponsorRequired   = errs.New("agent.sponsor_required", errs.KindUnprocessable, "Select a sponsoring user for the agent — every agent needs a named human owner.")
	ErrSponsorNotMember  = errs.New("agent.sponsor_not_member", errs.KindUnprocessable, "The sponsoring user must be a member of this organization.")
	ErrInvalidID         = errs.New("agent.invalid_id", errs.KindInvalid, "That identifier isn't valid.")
)
