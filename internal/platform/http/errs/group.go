package errs

// Group error codes — stable, namespaced machine identifiers for the
// internal/identity/groups domain. Clients branch and localize on these (never
// on the message text). Once shipped, a code MUST NOT change. Every identifier
// is prefixed with the `group` domain so it never collides with another
// bounded context.
const (
	CodeGroupNotFound = "group.not_found"
)

// Group errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrGroupNotFound`.
var (
	ErrGroupNotFound = New(CodeGroupNotFound, "That group doesn't exist.")
)
