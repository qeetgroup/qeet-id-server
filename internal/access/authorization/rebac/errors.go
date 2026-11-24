package rebac

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeSubjectInvalid          = "rebac.subject_invalid"
	CodeRelationRequired        = "rebac.relation_required"
	CodeObjectSubjectExclusive  = "rebac.object_subject_exclusive"
	CodeObjectOrSubjectRequired = "rebac.object_or_subject_required"
	CodeUserIDRelationRequired  = "rebac.user_id_relation_required"
	CodeObjectRelationRequired  = "rebac.object_relation_required"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrSubjectInvalid          = errs.New(CodeSubjectInvalid, errs.KindUnprocessable, "The subject must be in the form \"user:id\", \"type:id\", or \"type:id#relation\".")
	ErrRelationRequired        = errs.New(CodeRelationRequired, errs.KindUnprocessable, "A relation is required.")
	ErrObjectSubjectExclusive  = errs.New(CodeObjectSubjectExclusive, errs.KindInvalid, "Provide either an object or a subject, not both.")
	ErrObjectOrSubjectRequired = errs.New(CodeObjectOrSubjectRequired, errs.KindInvalid, "Provide an object or a subject to filter by.")
	ErrUserIDRelationRequired  = errs.New(CodeUserIDRelationRequired, errs.KindUnprocessable, "A user and a relation are required.")
	ErrObjectRelationRequired  = errs.New(CodeObjectRelationRequired, errs.KindInvalid, "An object and a relation are required.")
	// ErrReBACCheckTooComplex refuses a check, or a request's checks together,
	// that would follow more relationships than they may.
	ErrCheckTooComplex = errs.New("rebac.check_too_complex", errs.KindUnprocessable, "This check follows too many relationships to answer. Simplify the relationships it walks.")
)
