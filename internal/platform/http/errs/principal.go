package errs

// Service principal (OAuth client_credentials caller) error codes.
const (
	CodePrincipalInvalidCredentials = "principal.invalid_credentials"
	CodePrincipalDisabled           = "principal.disabled"
)

// Service-principal errors. The Message is what the end user sees — edit
// wording here, in one place. Auth failures deliberately share one generic
// message so a caller can't distinguish "unknown client" from "bad secret".
var (
	ErrPrincipalInvalidCredentials = New(CodePrincipalInvalidCredentials, KindUnauthenticated, "Invalid client credentials.")
	ErrPrincipalDisabled           = New(CodePrincipalDisabled, KindUnauthenticated, "This service principal has been disabled.")
)
