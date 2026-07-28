package errs

// OpenID Connect / OAuth2 provider error codes — stable, namespaced machine
// identifiers for the federation/oidc bounded context (authorization_code+PKCE,
// refresh, token-exchange, device, and CIBA grants, plus tenant-scoped client
// administration). Clients branch and localize on these codes, never on the
// message text. Once shipped a code MUST NOT change. Every name is prefixed
// `OIDC` so it never collides with another domain's catalog. Note: the OAuth
// token endpoint's own flat {"error","error_description"} shape (invalid_grant,
// authorization_pending, slow_down, …) is deliberately NOT modeled here.
const (
	// Client identity & authentication.
	CodeOIDCClientUnknown    = "oidc.client_unknown"
	CodeOIDCClientNotFound   = "oidc.client_not_found"
	CodeOIDCClientAuthFailed = "oidc.client_auth_failed"

	// Redirect URIs & scopes.
	CodeOIDCRedirectURIInvalid  = "oidc.redirect_uri_invalid"
	CodeOIDCRedirectURIMismatch = "oidc.redirect_uri_mismatch"
	CodeOIDCScopeNotPermitted   = "oidc.scope_not_permitted"
	CodeOIDCScopeExceedsSubject = "oidc.scope_exceeds_subject"

	// Grant types.
	CodeOIDCGrantTypeUnsupported = "oidc.grant_type_unsupported"
	CodeOIDCGrantTypeNotAllowed  = "oidc.grant_type_not_allowed"

	// Authorization code + PKCE.
	CodeOIDCAuthCodeInvalid                = "oidc.auth_code_invalid"
	CodeOIDCAuthCodeUsed                   = "oidc.auth_code_used"
	CodeOIDCAuthCodeExpired                = "oidc.auth_code_expired"
	CodeOIDCCodeVerifierRequired           = "oidc.code_verifier_required"
	CodeOIDCCodeVerifierInvalid            = "oidc.code_verifier_invalid"
	CodeOIDCCodeChallengeMethodUnsupported = "oidc.code_challenge_method_unsupported"

	// Token exchange (RFC 8693) subject/actor tokens.
	CodeOIDCSubjectTokenRequired          = "oidc.subject_token_required"
	CodeOIDCSubjectTokenTypeUnsupported   = "oidc.subject_token_type_unsupported"
	CodeOIDCSubjectTokenInvalid           = "oidc.subject_token_invalid"
	CodeOIDCSubjectTokenNoSubject         = "oidc.subject_token_no_subject"
	CodeOIDCRequestedTokenTypeUnsupported = "oidc.requested_token_type_unsupported"
	CodeOIDCActorTokenTypeUnsupported     = "oidc.actor_token_type_unsupported"
	CodeOIDCActorTokenInvalid             = "oidc.actor_token_invalid"

	// Refresh tokens.
	CodeOIDCRefreshTokenRequired       = "oidc.refresh_token_required"
	CodeOIDCRefreshTokenInvalid        = "oidc.refresh_token_invalid"
	CodeOIDCRefreshTokenClientMismatch = "oidc.refresh_token_client_mismatch"
	CodeOIDCRefreshTokenRevoked        = "oidc.refresh_token_revoked"
	CodeOIDCRefreshTokenExpired        = "oidc.refresh_token_expired"
	CodeOIDCRefreshTokenReuse          = "oidc.refresh_token_reuse"

	// Request shape & path parameters.
	CodeOIDCFormInvalid     = "oidc.form_invalid"
	CodeOIDCTenantIDInvalid = "oidc.tenant_id_invalid"
	CodeOIDCTenantMismatch  = "oidc.tenant_mismatch"
	CodeOIDCIDInvalid       = "oidc.id_invalid"

	// Grant & device administration.
	CodeOIDCGrantNotFound  = "oidc.grant_not_found"
	CodeOIDCDeviceNotFound = "oidc.device_not_found"

	// Device Authorization Grant (RFC 8628) user-code flow.
	CodeOIDCUserCodeInvalid      = "oidc.user_code_invalid"
	CodeOIDCUserCodeExpired      = "oidc.user_code_expired"
	CodeOIDCUserCodeRequired     = "oidc.user_code_required"
	CodeOIDCDeviceAlreadyDecided = "oidc.device_already_decided"
	CodeOIDCUserTenantMismatch   = "oidc.user_tenant_mismatch"

	// CIBA backchannel sign-in requests.
	CodeOIDCCIBARequestNotFound       = "oidc.ciba_request_not_found"
	CodeOIDCCIBARequestNotOwned       = "oidc.ciba_request_not_owned"
	CodeOIDCCIBARequestExpired        = "oidc.ciba_request_expired"
	CodeOIDCCIBARequestAlreadyDecided = "oidc.ciba_request_already_decided"

	// Client secret rotation & shadow-AI review.
	CodeOIDCPublicClientNoSecret = "oidc.public_client_no_secret"
	CodeOIDCReviewerRequired     = "oidc.reviewer_required"
)

// OIDC errors. The Message is what the end user sees — edit wording here, in one
// place. Handlers just `return errs.ErrOIDC…`, attaching a wrapped cause with
// `.Wrap(err)` when there's an underlying error worth logging. Errors marked
// AsRetryable() signal the client may refresh a token/session and try again.
var (
	// Client identity & authentication.
	ErrOIDCClientUnknown    = New(CodeOIDCClientUnknown, "Unknown client.")
	ErrOIDCClientNotFound   = New(CodeOIDCClientNotFound, "We couldn't find that OIDC client.")
	ErrOIDCClientAuthFailed = New(CodeOIDCClientAuthFailed, "Client authentication failed.")

	// Redirect URIs & scopes.
	ErrOIDCRedirectURIInvalid  = New(CodeOIDCRedirectURIInvalid, "That redirect URI is not registered for this client.")
	ErrOIDCRedirectURIMismatch = New(CodeOIDCRedirectURIMismatch, "The redirect URI doesn't match the one used to obtain this code.")
	ErrOIDCScopeNotPermitted   = New(CodeOIDCScopeNotPermitted, "One or more requested scopes aren't permitted for this client.")
	ErrOIDCScopeExceedsSubject = New(CodeOIDCScopeExceedsSubject, "The requested scope exceeds the subject token's scope.")

	// Grant types.
	ErrOIDCGrantTypeUnsupported = New(CodeOIDCGrantTypeUnsupported, "That grant type isn't supported.")
	ErrOIDCGrantTypeNotAllowed  = New(CodeOIDCGrantTypeNotAllowed, "This client isn't permitted to use that grant type.")

	// Authorization code + PKCE.
	ErrOIDCAuthCodeInvalid                = New(CodeOIDCAuthCodeInvalid, "That authorization code is invalid.")
	ErrOIDCAuthCodeUsed                   = New(CodeOIDCAuthCodeUsed, "That authorization code has already been used.")
	ErrOIDCAuthCodeExpired                = New(CodeOIDCAuthCodeExpired, "That authorization code has expired. Start again to get a new one.")
	ErrOIDCCodeVerifierRequired           = New(CodeOIDCCodeVerifierRequired, "A PKCE code_verifier is required.")
	ErrOIDCCodeVerifierInvalid            = New(CodeOIDCCodeVerifierInvalid, "The PKCE code_verifier is invalid.")
	ErrOIDCCodeChallengeMethodUnsupported = New(CodeOIDCCodeChallengeMethodUnsupported, "That PKCE code_challenge_method isn't supported.")

	// Token exchange (RFC 8693) subject/actor tokens.
	ErrOIDCSubjectTokenRequired          = New(CodeOIDCSubjectTokenRequired, "A subject_token is required.")
	ErrOIDCSubjectTokenTypeUnsupported   = New(CodeOIDCSubjectTokenTypeUnsupported, "That subject_token_type isn't supported.")
	ErrOIDCSubjectTokenInvalid           = New(CodeOIDCSubjectTokenInvalid, "The subject token is invalid or has expired.").AsRetryable()
	ErrOIDCSubjectTokenNoSubject         = New(CodeOIDCSubjectTokenNoSubject, "The subject token doesn't identify a user.")
	ErrOIDCRequestedTokenTypeUnsupported = New(CodeOIDCRequestedTokenTypeUnsupported, "That requested_token_type isn't supported.")
	ErrOIDCActorTokenTypeUnsupported     = New(CodeOIDCActorTokenTypeUnsupported, "That actor_token_type isn't supported.")
	ErrOIDCActorTokenInvalid             = New(CodeOIDCActorTokenInvalid, "The actor token is invalid or has expired.").AsRetryable()

	// Refresh tokens.
	ErrOIDCRefreshTokenRequired       = New(CodeOIDCRefreshTokenRequired, "A refresh_token is required.")
	ErrOIDCRefreshTokenInvalid        = New(CodeOIDCRefreshTokenInvalid, "That refresh token is invalid.").AsRetryable()
	ErrOIDCRefreshTokenClientMismatch = New(CodeOIDCRefreshTokenClientMismatch, "That refresh token wasn't issued to this client.")
	ErrOIDCRefreshTokenRevoked        = New(CodeOIDCRefreshTokenRevoked, "That refresh token has been revoked.")
	ErrOIDCRefreshTokenExpired        = New(CodeOIDCRefreshTokenExpired, "That refresh token has expired.").AsRetryable()
	ErrOIDCRefreshTokenReuse          = New(CodeOIDCRefreshTokenReuse, "That refresh token was already used; all related tokens have been revoked.")

	// Request shape & path parameters.
	ErrOIDCFormInvalid     = New(CodeOIDCFormInvalid, "The request form couldn't be parsed.")
	ErrOIDCTenantIDInvalid = New(CodeOIDCTenantIDInvalid, "That tenant ID is invalid.")
	ErrOIDCTenantMismatch  = New(CodeOIDCTenantMismatch, "You can only access your own tenant.")
	ErrOIDCIDInvalid       = New(CodeOIDCIDInvalid, "That ID is invalid.")

	// Grant & device administration.
	ErrOIDCGrantNotFound  = New(CodeOIDCGrantNotFound, "We couldn't find that grant.")
	ErrOIDCDeviceNotFound = New(CodeOIDCDeviceNotFound, "We couldn't find that device authorization.")

	// Device Authorization Grant (RFC 8628) user-code flow.
	ErrOIDCUserCodeInvalid      = New(CodeOIDCUserCodeInvalid, "That code isn't recognized.")
	ErrOIDCUserCodeExpired      = New(CodeOIDCUserCodeExpired, "That code has expired. Request a new one on your device.")
	ErrOIDCUserCodeRequired     = New(CodeOIDCUserCodeRequired, "Enter the code shown on your device.")
	ErrOIDCDeviceAlreadyDecided = New(CodeOIDCDeviceAlreadyDecided, "This device authorization has already been decided.")
	ErrOIDCUserTenantMismatch   = New(CodeOIDCUserTenantMismatch, "You don't belong to this client's tenant.")

	// CIBA backchannel sign-in requests.
	ErrOIDCCIBARequestNotFound       = New(CodeOIDCCIBARequestNotFound, "We couldn't find that sign-in request.")
	ErrOIDCCIBARequestNotOwned       = New(CodeOIDCCIBARequestNotOwned, "That sign-in request isn't yours.")
	ErrOIDCCIBARequestExpired        = New(CodeOIDCCIBARequestExpired, "That sign-in request has expired.")
	ErrOIDCCIBARequestAlreadyDecided = New(CodeOIDCCIBARequestAlreadyDecided, "That sign-in request has already been decided.")

	// Client secret rotation & shadow-AI review.
	ErrOIDCPublicClientNoSecret = New(CodeOIDCPublicClientNoSecret, "Public clients have no secret to rotate.")
	ErrOIDCReviewerRequired     = New(CodeOIDCReviewerRequired, "This review must be attributed to a signed-in user.")
)
