package user

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeImportSourceInvalid = "user.import_source_invalid"
	CodeImportEmpty         = "user.import_empty"
	CodeCredentialsShared   = "user.credentials_shared"
	CodeManagedHere         = "user.managed_here"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrImportSourceInvalid = errs.New(CodeImportSourceInvalid, errs.KindInvalid, "Choose a supported import source (auth0, cognito, or azure_b2c).")
	ErrImportFileTooLarge  = errs.New("user.import_file_too_large", errs.KindUnprocessable, "That export file is too large. The maximum is 10 MB.")
	ErrImportEmpty         = errs.New(CodeImportEmpty, errs.KindUnprocessable, "We couldn't find any user records in that export.")
	ErrImportBatchTooLarge = errs.New("user.import_batch_too_large", errs.KindUnprocessable, "That import is too large. Import at most 1000 users per request.")
	ErrCredentialsShared   = errs.New(CodeCredentialsShared, errs.KindForbidden, "This person also belongs to another organization, so only they can change their password or two-step verification. Ask them to reset their password from the sign-in page.")
	ErrManagedHere         = errs.New(CodeManagedHere, errs.KindConflict, "This organization manages this person's account. Suspend or delete the account instead.")
)
