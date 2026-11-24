package errs

// API-key errors. The Message is what the end user sees — edit wording here, in
// one place. The presented-key failures (malformed, unknown, bad secret) share
// one message so a caller can't distinguish why a key was rejected.
var (
	ErrAPIKeyNotFound = New("apikey.not_found", KindNotFound, "That API key doesn't exist.")
)
