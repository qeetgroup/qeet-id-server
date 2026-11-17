package errs

// ReBAC (relationship-based access control) error codes.
const (
	CodeReBACObjectInvalid           = "rebac.object_invalid"
	CodeReBACSubjectInvalid          = "rebac.subject_invalid"
	CodeReBACRelationRequired        = "rebac.relation_required"
	CodeReBACObjectSubjectExclusive  = "rebac.object_subject_exclusive"
	CodeReBACObjectOrSubjectRequired = "rebac.object_or_subject_required"
	CodeReBACUserIDRelationRequired  = "rebac.user_id_relation_required"
	CodeReBACObjectRelationRequired  = "rebac.object_relation_required"
	CodeReBACCheckTooComplex         = "rebac.check_too_complex"
)

// ReBAC errors. The Message is what the caller writing or querying relationship
// tuples sees.
var (
	ErrReBACObjectInvalid           = New(CodeReBACObjectInvalid, "The object must be in the form \"type:id\".")
	ErrReBACSubjectInvalid          = New(CodeReBACSubjectInvalid, "The subject must be in the form \"user:id\", \"type:id\", or \"type:id#relation\".")
	ErrReBACRelationRequired        = New(CodeReBACRelationRequired, "A relation is required.")
	ErrReBACObjectSubjectExclusive  = New(CodeReBACObjectSubjectExclusive, "Provide either an object or a subject, not both.")
	ErrReBACObjectOrSubjectRequired = New(CodeReBACObjectOrSubjectRequired, "Provide an object or a subject to filter by.")
	ErrReBACUserIDRelationRequired  = New(CodeReBACUserIDRelationRequired, "A user and a relation are required.")
	ErrReBACObjectRelationRequired  = New(CodeReBACObjectRelationRequired, "An object and a relation are required.")
	// ErrReBACCheckTooComplex refuses a check, or a request's checks together,
	// that would follow more relationships than they may.
	ErrReBACCheckTooComplex = New(CodeReBACCheckTooComplex, "This check follows too many relationships to answer. Simplify the relationships it walks.")
)
