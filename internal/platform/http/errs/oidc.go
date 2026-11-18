package errs

// OpenID Connect and OAuth 2.0 provider error codes. The token endpoint's own
// {"error", "error_description"} responses (invalid_grant, slow_down, …) are not
// modeled here.
const (
	CodeOIDCClientAuthFailed = "oidc.client_auth_failed"

	CodeOIDCRedirectURINotRegistered = "oidc.redirect_uri_not_registered"
)

// OIDC errors. A retryable error means the client may refresh its token or
// session and try again. ErrOIDCRedirectURINotRegistered is shown to the user,
// never sent to the unregistered address.
var (
	ErrOIDCClientAuthFailed = New(CodeOIDCClientAuthFailed, KindUnauthenticated, "Client authentication failed.")

	ErrOIDCRedirectURINotRegistered = New(CodeOIDCRedirectURINotRegistered, KindInvalid, "This application didn't register that return address, so we can't send you back to it.")
)
