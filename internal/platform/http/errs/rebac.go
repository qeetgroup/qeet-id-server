package errs

// ReBAC (relationship-based access control) error codes — stable, namespaced
// machine identifiers for relation-tuple validation and the object/subject
// query filters. Clients branch and localize on these, never on the message
// text. Once shipped, a code MUST NOT change.
const (
	CodeReBACObjectInvalid           = "rebac.object_invalid"
	CodeReBACSubjectInvalid          = "rebac.subject_invalid"
	CodeReBACRelationRequired        = "rebac.relation_required"
	CodeReBACObjectSubjectExclusive  = "rebac.object_subject_exclusive"
	CodeReBACObjectOrSubjectRequired = "rebac.object_or_subject_required"
	CodeReBACUserIDRelationRequired  = "rebac.user_id_relation_required"
	CodeReBACObjectRelationRequired  = "rebac.object_relation_required"
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
)
