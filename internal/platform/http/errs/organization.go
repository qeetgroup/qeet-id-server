package errs

// Organization error codes.
const (
	CodeOrgSlugTaken = "organization.slug_taken"
)

var (
	ErrOrgSlugTaken = New(CodeOrgSlugTaken, KindConflict, "That organization URL is already taken. Choose another one.")
)
