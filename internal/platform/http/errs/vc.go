package errs

// Verifiable-credential errors. The Message is what the end user sees. Handlers
// just `return errs.ErrVCCredentialNotFound`, attaching a wrapped cause with
// `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrVCCredentialNotFound = New("vc.credential_not_found", KindNotFound, "We couldn't find that credential.")
)
