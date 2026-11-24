package errs

// Agent (AI-agent identity) error codes.
const (
	CodeAgentTokenInvalid = "agent.token_invalid"
	CodeAgentInactive     = "agent.inactive"
)

// Agent errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return agent.ErrNotFound`, attaching a wrapped
// cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrAgentTokenInvalid = New(CodeAgentTokenInvalid, KindUnauthenticated, "Invalid agent credentials.")
	ErrAgentInactive     = New(CodeAgentInactive, KindUnauthenticated, "This agent isn't active.")
)
