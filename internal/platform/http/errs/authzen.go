package errs

// AuthZEN error codes — stable, namespaced machine identifiers for the OpenID
// AuthZEN evaluation request validation (the Policy Decision Point facade).
// Clients branch and localize on these, never on the message text. Once
// shipped, a code MUST NOT change.
const (
	CodeAuthZENSubjectIDRequired  = "authzen.subject_id_required"
	CodeAuthZENActionNameRequired = "authzen.action_name_required"
	CodeAuthZENSubjectIDInvalid   = "authzen.subject_id_invalid"
	CodeAuthZENResourceRequired   = "authzen.resource_required"
)

// AuthZEN errors. The Message is what the caller of the evaluation endpoint
// sees when a request is malformed.
var (
	ErrAuthZENSubjectIDRequired  = New(CodeAuthZENSubjectIDRequired, "subject.id is required.")
	ErrAuthZENActionNameRequired = New(CodeAuthZENActionNameRequired, "action.name is required.")
	ErrAuthZENSubjectIDInvalid   = New(CodeAuthZENSubjectIDInvalid, "subject.id must be a valid UUID.")
	ErrAuthZENResourceRequired   = New(CodeAuthZENResourceRequired, "resource.type and resource.id are required.")
)
