package authzen

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeSubjectIDRequired  = "authzen.subject_id_required"
	CodeTooManyEvaluations = "authzen.too_many_evaluations"
	CodeSemanticInvalid    = "authzen.evaluations_semantic_invalid"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrSubjectIDRequired  = errs.New(CodeSubjectIDRequired, errs.KindUnprocessable, "subject.id is required.")
	ErrActionNameRequired = errs.New("authzen.action_name_required", errs.KindUnprocessable, "action.name is required.")
	ErrSubjectIDInvalid   = errs.New("authzen.subject_id_invalid", errs.KindUnprocessable, "subject.id must be a valid UUID.")
	ErrResourceRequired   = errs.New("authzen.resource_required", errs.KindUnprocessable, "resource.type and resource.id are required.")
	ErrTooManyEvaluations = errs.New(CodeTooManyEvaluations, errs.KindUnprocessable, "Send at most 100 evaluations in one request.")
	ErrSemanticInvalid    = errs.New(CodeSemanticInvalid, errs.KindUnprocessable, "options.evaluations_semantic must be execute_all, deny_on_first_deny or permit_on_first_permit.")
)
