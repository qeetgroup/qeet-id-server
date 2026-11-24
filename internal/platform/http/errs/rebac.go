package errs

// ReBAC (relationship-based access control) error codes.
const (
	CodeReBACObjectInvalid = "rebac.object_invalid"
)

// ReBAC errors. The Message is what the caller writing or querying relationship
// tuples sees.
var (
	ErrReBACObjectInvalid = New(CodeReBACObjectInvalid, KindUnprocessable, "The object must be in the form \"type:id\".")
)
