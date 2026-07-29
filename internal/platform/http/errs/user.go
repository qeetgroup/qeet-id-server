package errs

// User error codes — stable, namespaced machine identifiers for the
// internal/identity/users domain (currently the bulk-import surface; the
// "email already exists" case reuses ErrAuthEmailExists). Clients branch and
// localize on these (never on the message text). Once shipped, a code MUST NOT
// change. Every identifier is prefixed with the `user` domain so it never
// collides with another bounded context.
const (
	CodeUserImportSourceInvalid = "user.import_source_invalid"
	CodeUserImportFileTooLarge  = "user.import_file_too_large"
	CodeUserImportEmpty         = "user.import_empty"
	CodeUserImportBatchTooLarge = "user.import_batch_too_large"
)

// User errors. The Message is what the end user sees — edit wording here, in
// one place. These are re-tried with a different payload (a smaller/valid file),
// so none are marked retryable.
var (
	ErrUserImportSourceInvalid = New(CodeUserImportSourceInvalid, "Choose a supported import source (auth0, cognito, or azure_b2c).")
	ErrUserImportFileTooLarge  = New(CodeUserImportFileTooLarge, "That export file is too large. The maximum is 10 MB.")
	ErrUserImportEmpty         = New(CodeUserImportEmpty, "We couldn't find any user records in that export.")
	ErrUserImportBatchTooLarge = New(CodeUserImportBatchTooLarge, "That import is too large. Import at most 1000 users per request.")
)
