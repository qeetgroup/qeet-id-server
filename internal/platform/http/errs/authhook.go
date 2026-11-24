package errs

// Auth hook error codes.
const (
	CodeAuthHookDenied = "authhook.denied"
)

// Auth-hook errors. The Message is what the end user sees — edit wording here,
// in one place. ErrAuthHookDenied carries a safe default; the Run path overrides
// it with the organization policy's own message via WithMessage when one is supplied.
var (
	ErrAuthHookDenied = New(CodeAuthHookDenied, KindForbidden, "Sign-in was blocked by your organization's policy.")
)
