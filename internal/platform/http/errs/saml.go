package errs

// SAML error codes, for both the service provider and identity provider sides.
const (
	CodeSAMLAssertionInvalid = "saml.assertion_invalid"
)

// SAML errors. Message is the end-user-facing text; edit wording here. Handlers
// just `return errs.ErrSAML<Reason>` (optionally `.Wrap(err)` for logs).
var (
	ErrSAMLAssertionInvalid = New(CodeSAMLAssertionInvalid, KindUnauthenticated, "We couldn't validate the SAML assertion.")
)
