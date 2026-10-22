package errs

// User error codes. "Email already exists" reuses ErrAuthEmailExists.
const (
	CodeUserImportSourceInvalid = "user.import_source_invalid"
	CodeUserImportFileTooLarge  = "user.import_file_too_large"
	CodeUserImportEmpty         = "user.import_empty"
	CodeUserImportBatchTooLarge = "user.import_batch_too_large"

	// Who manages an account.
	CodeUserManagedElsewhere  = "user.managed_elsewhere"
	CodeUserCredentialsShared = "user.credentials_shared"
	CodeUserManagedHere       = "user.managed_here"
)

// User errors. The Message is what the end user sees — edit wording here, in
// one place. These are re-tried with a different payload (a smaller/valid file),
// so none are marked retryable.
var (
	ErrUserImportSourceInvalid = New(CodeUserImportSourceInvalid, "Choose a supported import source (auth0, cognito, or azure_b2c).")
	ErrUserImportFileTooLarge  = New(CodeUserImportFileTooLarge, "That export file is too large. The maximum is 10 MB.")
	ErrUserImportEmpty         = New(CodeUserImportEmpty, "We couldn't find any user records in that export.")
	ErrUserImportBatchTooLarge = New(CodeUserImportBatchTooLarge, "That import is too large. Import at most 1000 users per request.")

	ErrUserManagedElsewhere  = New(CodeUserManagedElsewhere, "This person's account is managed outside this organization. Remove them from this organization instead.")
	ErrUserCredentialsShared = New(CodeUserCredentialsShared, "This person also belongs to another organization, so only they can change their password or two-step verification. Ask them to reset their password from the sign-in page.")
	ErrUserManagedHere       = New(CodeUserManagedHere, "This organization manages this person's account. Suspend or delete the account instead.")
)
