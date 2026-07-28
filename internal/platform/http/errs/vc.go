package errs

// Verifiable-credential (JWT-VC) error codes — stable, namespaced machine
// identifiers. Clients branch and localize on these, never on the message text.
const (
	CodeVCSubjectTypeRequired = "vc.subject_type_required"
	CodeVCClaimsInvalid       = "vc.claims_invalid"
	CodeVCCredentialRequired  = "vc.credential_required"
	CodeVCCredentialNotFound  = "vc.credential_not_found"
)

// Verifiable-credential errors. The Message is what the end user sees. Handlers
// just `return errs.ErrVCCredentialNotFound`, attaching a wrapped cause with
// `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrVCSubjectTypeRequired = New(CodeVCSubjectTypeRequired, "A credential subject and type are required.")
	ErrVCClaimsInvalid       = New(CodeVCClaimsInvalid, "Credential claims must be a valid JSON object.")
	ErrVCCredentialRequired  = New(CodeVCCredentialRequired, "A credential (JWT) is required.")
	ErrVCCredentialNotFound  = New(CodeVCCredentialNotFound, "We couldn't find that credential.")
)
