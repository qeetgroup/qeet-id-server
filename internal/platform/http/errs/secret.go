package errs

// Secret vault errors. The Message is what the end user sees. Handlers just
// `return errs.ErrSecretNotFound`, attaching a wrapped cause with `.Wrap(err)`
// when there's an underlying error worth logging.
var (
	ErrSecretNotFound = New("secret.not_found", KindNotFound, "We couldn't find that secret.")
)
