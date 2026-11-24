package errs

// Group error codes.
const (
	CodeGroupNotFound = "group.not_found"
)

// Group errors.
var (
	ErrGroupNotFound = New(CodeGroupNotFound, KindNotFound, "That group doesn't exist.")
)
