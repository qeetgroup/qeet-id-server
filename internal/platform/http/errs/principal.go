package errs

// Service principal (OAuth client_credentials caller) error codes.
const (
	CodePrincipalNotFound           = "principal.not_found"
	CodePrincipalInvalidCredentials = "principal.invalid_credentials"
	CodePrincipalDisabled           = "principal.disabled"
	CodePrincipalGrantUnsupported   = "principal.grant_unsupported"
	CodePrincipalInvalidID          = "principal.invalid_id"
)

// Service-principal errors. The Message is what the end user sees — edit
// wording here, in one place. Auth failures deliberately share one generic
// message so a caller can't distinguish "unknown client" from "bad secret".
var (
	ErrPrincipalNotFound           = New(CodePrincipalNotFound, "That service principal doesn't exist.")
	ErrPrincipalInvalidCredentials = New(CodePrincipalInvalidCredentials, "Invalid client credentials.")
	ErrPrincipalDisabled           = New(CodePrincipalDisabled, "This service principal has been disabled.")
	ErrPrincipalGrantUnsupported   = New(CodePrincipalGrantUnsupported, "Only the client_credentials grant type is supported.")
	ErrPrincipalInvalidID          = New(CodePrincipalInvalidID, "That identifier isn't valid.")
)
