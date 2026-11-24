package errs

// OpenID Connect and OAuth 2.0 provider error codes. The token endpoint's own
// {"error", "error_description"} responses (invalid_grant, slow_down, …) are not
// modeled here.
const (
	CodeOIDCClientAuthFailed = "oidc.client_auth_failed"
)

// OIDC errors. A retryable error means the client may refresh its token or
// session and try again.
var (
	ErrOIDCClientAuthFailed = New(CodeOIDCClientAuthFailed, KindUnauthenticated, "Client authentication failed.")
)
