package errs

// Organization / tenant error codes.
const (
	CodeOrgSlugTaken = "tenant.slug_taken"
)

var (
	ErrOrgSlugTaken = New(CodeOrgSlugTaken, "That organization URL is already taken. Choose another one.")
)
