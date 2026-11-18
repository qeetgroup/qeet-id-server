package errs

// User error codes. "Email already exists" reuses ErrAuthEmailExists.
const (

	// Who manages an account.
	CodeUserManagedElsewhere = "user.managed_elsewhere"
	CodeUserDomainManaged    = "user.domain_managed_elsewhere"
)

// User errors. The Message is what the end user sees — edit wording here, in
// one place. These are re-tried with a different payload (a smaller/valid file),
// so none are marked retryable.
var (
	ErrUserManagedElsewhere = New(CodeUserManagedElsewhere, KindForbidden, "This person's account is managed outside this organization. Remove them from this organization instead.")
	ErrUserDomainManaged    = New(CodeUserDomainManaged, KindConflict, "That address is on a domain another organization has verified, so only that organization can create its account.")
)
