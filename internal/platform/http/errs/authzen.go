package errs

// AuthZEN evaluation request error codes.
const (
	CodeAuthZENSubjectIDRequired  = "authzen.subject_id_required"
	CodeAuthZENActionNameRequired = "authzen.action_name_required"
	CodeAuthZENSubjectIDInvalid   = "authzen.subject_id_invalid"
	CodeAuthZENResourceRequired   = "authzen.resource_required"

	CodeAuthZENTooManyEvaluations = "authzen.too_many_evaluations"
	CodeAuthZENSemanticInvalid    = "authzen.evaluations_semantic_invalid"
)

// AuthZEN errors. The Message is what the caller of the evaluation endpoint
// sees when a request is malformed.
var (
	ErrAuthZENSubjectIDRequired  = New(CodeAuthZENSubjectIDRequired, "subject.id is required.")
	ErrAuthZENActionNameRequired = New(CodeAuthZENActionNameRequired, "action.name is required.")
	ErrAuthZENSubjectIDInvalid   = New(CodeAuthZENSubjectIDInvalid, "subject.id must be a valid UUID.")
	ErrAuthZENResourceRequired   = New(CodeAuthZENResourceRequired, "resource.type and resource.id are required.")

	ErrAuthZENTooManyEvaluations = New(CodeAuthZENTooManyEvaluations, "Send at most 100 evaluations in one request.")
	ErrAuthZENSemanticInvalid    = New(CodeAuthZENSemanticInvalid, "options.evaluations_semantic must be execute_all, deny_on_first_deny or permit_on_first_permit.")
)
