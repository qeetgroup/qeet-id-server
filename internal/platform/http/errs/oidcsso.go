package errs

// Error codes for an organization's own OpenID Connect identity provider
// (enterprise OIDC connections): their administration and sign-in.
const (
	CodeOIDCSSOIDTokenInvalid = "oidc_connection.id_token_invalid"
)

// Enterprise OIDC errors. Every way an ID token can fail validation answers
// ErrOIDCSSOIDTokenInvalid, so a caller learns nothing about which check failed.
var (
	ErrOIDCSSOIDTokenInvalid = New(CodeOIDCSSOIDTokenInvalid, KindUnauthenticated, "We couldn't validate the sign-in from your organization's provider.")
)
