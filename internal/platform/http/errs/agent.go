package errs

// Agent (AI-agent identity) error codes — stable, namespaced machine
// identifiers for the internal/developer/agents domain. Clients branch and
// localize on these (never on the message text). Once shipped, a code MUST NOT
// change. Every identifier is prefixed with the `agent` domain so it never
// collides with another bounded context.
const (
	CodeAgentNotFound          = "agent.not_found"
	CodeAgentStatusInvalid     = "agent.status_invalid"
	CodeAgentDecommissioned    = "agent.decommissioned"
	CodeAgentTransitionInvalid = "agent.transition_invalid"
	CodeAgentNameRequired      = "agent.name_required"
	CodeAgentSponsorRequired   = "agent.sponsor_required"
	CodeAgentSponsorNotMember  = "agent.sponsor_not_member"
	CodeAgentTokenInvalid      = "agent.token_invalid"
	CodeAgentInactive          = "agent.inactive"
	CodeAgentInvalidID         = "agent.invalid_id"
	CodeAgentTenantMismatch    = "agent.tenant_mismatch"
)

// Agent errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrAgentNotFound`, attaching a wrapped
// cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrAgentNotFound          = New(CodeAgentNotFound, "That agent doesn't exist.")
	ErrAgentStatusInvalid     = New(CodeAgentStatusInvalid, "That agent status isn't valid.")
	ErrAgentDecommissioned    = New(CodeAgentDecommissioned, "This agent has been decommissioned and can no longer be changed.")
	ErrAgentTransitionInvalid = New(CodeAgentTransitionInvalid, "This agent can't move to that status.")
	ErrAgentNameRequired      = New(CodeAgentNameRequired, "Enter a name for the agent.")
	ErrAgentSponsorRequired   = New(CodeAgentSponsorRequired, "Select a sponsoring user for the agent — every agent needs a named human owner.")
	ErrAgentSponsorNotMember  = New(CodeAgentSponsorNotMember, "The sponsoring user must be a member of this tenant.")
	ErrAgentTokenInvalid      = New(CodeAgentTokenInvalid, "Invalid agent credentials.")
	ErrAgentInactive          = New(CodeAgentInactive, "This agent isn't active.")
	ErrAgentInvalidID         = New(CodeAgentInvalidID, "That identifier isn't valid.")
	ErrAgentTenantMismatch    = New(CodeAgentTenantMismatch, "You can only manage agents in your own tenant.")
)
