package oidc

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeClientNotFound = "oidc.client_not_found"
	// Redirect URIs & scopes.
	CodeRedirectURIInvalid    = "oidc.redirect_uri_invalid"
	CodeWebOriginInvalid      = "oidc.web_origin_invalid"
	CodeRedirectURIMismatch   = "oidc.redirect_uri_mismatch"
	CodeConsentRequestInvalid = "oidc.consent_request_invalid"
	CodeScopeNotPermitted     = "oidc.scope_not_permitted"
	CodeScopeExceedsSubject   = "oidc.scope_exceeds_subject"
	// Grant types.
	CodeGrantTypeUnsupported = "oidc.grant_type_unsupported"
	CodeGrantTypeNotAllowed  = "oidc.grant_type_not_allowed"
	CodeUnsupportedFlow      = "oidc.unsupported_flow"
	// Authorization code + PKCE.
	CodeAuthCodeInvalid                = "oidc.auth_code_invalid"
	CodeAuthCodeUsed                   = "oidc.auth_code_used"
	CodeAuthCodeExpired                = "oidc.auth_code_expired"
	CodeCodeChallengeRequired          = "oidc.code_challenge_required"
	CodeCodeVerifierRequired           = "oidc.code_verifier_required"
	CodeCodeVerifierInvalid            = "oidc.code_verifier_invalid"
	CodeCodeChallengeMethodUnsupported = "oidc.code_challenge_method_unsupported"
	CodePKCEExemptionInvalid           = "oidc.pkce_exemption_invalid"
	CodeResourceInvalid                = "oidc.resource_invalid"
	CodeResourceExists                 = "oidc.resource_exists"
	CodeResourceDomainTaken            = "oidc.resource_domain_taken"
	CodeResourceDomainUnverified       = "oidc.resource_domain_unverified"
	CodeResourceReserved               = "oidc.resource_reserved"
	CodeResourceNotFound               = "oidc.resource_not_found"
	CodeRefreshTokenInvalid            = "oidc.refresh_token_invalid"
	CodeRefreshTokenClientMismatch     = "oidc.refresh_token_client_mismatch"
	CodeRefreshTokenRevoked            = "oidc.refresh_token_revoked"
	CodeRefreshTokenExpired            = "oidc.refresh_token_expired"
	CodeRefreshTokenReuse              = "oidc.refresh_token_reuse"
	// Grant & device administration.
	CodeGrantNotFound             = "oidc.grant_not_found"
	CodeDeviceNotFound            = "oidc.device_not_found"
	CodeUserCodeExpired           = "oidc.user_code_expired"
	CodeDeviceAlreadyDecided      = "oidc.device_already_decided"
	CodeUserOrganizationMismatch  = "oidc.user_organization_mismatch"
	CodeCIBARequestNotOwned       = "oidc.ciba_request_not_owned"
	CodeCIBARequestAlreadyDecided = "oidc.ciba_request_already_decided"
	// Client secret rotation & shadow-AI review.
	CodePublicClientNoSecret = "oidc.public_client_no_secret"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	// Client identity & authentication.
	ErrClientUnknown  = errs.New("oidc.client_unknown", errs.KindInvalid, "Unknown client.")
	ErrClientNotFound = errs.New(CodeClientNotFound, errs.KindNotFound, "We couldn't find that OIDC client.")
	// Redirect URIs & scopes.
	ErrRedirectURIInvalid    = errs.New(CodeRedirectURIInvalid, errs.KindInvalid, "That redirect URI is not registered for this client.")
	ErrWebOriginInvalid      = errs.New(CodeWebOriginInvalid, errs.KindUnprocessable, "A web origin is a scheme, host and optional port, such as https://app.example.com: https, or http only for localhost.")
	ErrRedirectURIMismatch   = errs.New(CodeRedirectURIMismatch, errs.KindInvalid, "The redirect URI doesn't match the one used to obtain this code.")
	ErrConsentRequestInvalid = errs.New(CodeConsentRequestInvalid, errs.KindInvalid, "This sign-in request has expired or isn't valid. Start signing in again from the application.")
	ErrScopeNotPermitted     = errs.New(CodeScopeNotPermitted, errs.KindInvalid, "One or more requested scopes aren't permitted for this client.")
	ErrScopeExceedsSubject   = errs.New(CodeScopeExceedsSubject, errs.KindForbidden, "The requested scope exceeds the subject token's scope.")
	// Grant types.
	ErrGrantTypeUnsupported = errs.New(CodeGrantTypeUnsupported, errs.KindInvalid, "That grant type isn't supported.")
	ErrGrantTypeNotAllowed  = errs.New(CodeGrantTypeNotAllowed, errs.KindForbidden, "This client isn't permitted to use that grant type.")
	ErrUnsupportedFlow      = errs.New(CodeUnsupportedFlow, errs.KindInvalid, "A public application can't use token exchange or backchannel sign-in. Register it as confidential.")
	// Authorization code + PKCE.
	ErrAuthCodeInvalid                = errs.New(CodeAuthCodeInvalid, errs.KindInvalid, "That authorization code is invalid.")
	ErrAuthCodeUsed                   = errs.New(CodeAuthCodeUsed, errs.KindInvalid, "That authorization code has already been used.")
	ErrAuthCodeExpired                = errs.New(CodeAuthCodeExpired, errs.KindInvalid, "That authorization code has expired. Start again to get a new one.")
	ErrCodeChallengeRequired          = errs.New(CodeCodeChallengeRequired, errs.KindInvalid, "A PKCE code_challenge (S256) is required.")
	ErrCodeChallengeInvalid           = errs.New("oidc.code_challenge_invalid", errs.KindInvalid, "The PKCE code_challenge is invalid.")
	ErrCodeVerifierRequired           = errs.New(CodeCodeVerifierRequired, errs.KindInvalid, "A PKCE code_verifier is required.")
	ErrCodeVerifierInvalid            = errs.New(CodeCodeVerifierInvalid, errs.KindInvalid, "The PKCE code_verifier is invalid.")
	ErrCodeChallengeMethodUnsupported = errs.New(CodeCodeChallengeMethodUnsupported, errs.KindInvalid, "That PKCE code_challenge_method isn't supported.")
	ErrNonceInvalid                   = errs.New("oidc.nonce_invalid", errs.KindInvalid, "The nonce is too long (at most 255 characters).")
	ErrInsufficientScope              = errs.New("oidc.insufficient_scope", errs.KindForbidden, "This token wasn't issued with the openid scope.")
	ErrExchangeDepthExceeded          = errs.New("oidc.exchange_depth_exceeded", errs.KindInvalid, "This token was already exchanged as many times as allowed.")
	ErrResourceInvalid                = errs.New(CodeResourceInvalid, errs.KindUnprocessable, "A resource identifier is an absolute URI without a fragment, such as https://api.example.com.")
	ErrResourceExists                 = errs.New(CodeResourceExists, errs.KindConflict, "That resource is already registered.")
	ErrResourceDomainTaken            = errs.New(CodeResourceDomainTaken, errs.KindConflict, "That resource is on a domain another organization has verified.")
	ErrResourceDomainUnverified       = errs.New(CodeResourceDomainUnverified, errs.KindForbidden, "Verify the resource's domain for your organization before you register it.")
	ErrResourceReserved               = errs.New(CodeResourceReserved, errs.KindConflict, "That resource identifier belongs to Qeet ID itself.")
	ErrResourceNotFound               = errs.New(CodeResourceNotFound, errs.KindNotFound, "We couldn't find that resource.")
	ErrPKCEExemptionInvalid           = errs.New(CodePKCEExemptionInvalid, errs.KindUnprocessable, "A PKCE exemption is for a confidential application, and must end in the future and within 90 days.")
	// Token exchange (RFC 8693) subject/actor tokens.
	ErrSubjectTokenRequired          = errs.New("oidc.subject_token_required", errs.KindInvalid, "A subject_token is required.")
	ErrSubjectTokenTypeUnsupported   = errs.New("oidc.subject_token_type_unsupported", errs.KindInvalid, "That subject_token_type isn't supported.")
	ErrSubjectTokenInvalid           = errs.New("oidc.subject_token_invalid", errs.KindUnauthenticated, "The subject token is invalid or has expired.").AsRetryable()
	ErrSubjectTokenNoSubject         = errs.New("oidc.subject_token_no_subject", errs.KindUnauthenticated, "The subject token doesn't identify a user.")
	ErrRequestedTokenTypeUnsupported = errs.New("oidc.requested_token_type_unsupported", errs.KindInvalid, "That requested_token_type isn't supported.")
	ErrActorTokenTypeUnsupported     = errs.New("oidc.actor_token_type_unsupported", errs.KindInvalid, "That actor_token_type isn't supported.")
	ErrActorTokenInvalid             = errs.New("oidc.actor_token_invalid", errs.KindUnauthenticated, "The actor token is invalid or has expired.").AsRetryable()
	// Refresh tokens.
	ErrRefreshTokenRequired       = errs.New("oidc.refresh_token_required", errs.KindInvalid, "A refresh_token is required.")
	ErrRefreshTokenInvalid        = errs.New(CodeRefreshTokenInvalid, errs.KindUnauthenticated, "That refresh token is invalid.").AsRetryable()
	ErrRefreshTokenClientMismatch = errs.New(CodeRefreshTokenClientMismatch, errs.KindUnauthenticated, "That refresh token wasn't issued to this client.")
	ErrRefreshTokenRevoked        = errs.New(CodeRefreshTokenRevoked, errs.KindUnauthenticated, "That refresh token has been revoked.")
	ErrRefreshTokenExpired        = errs.New(CodeRefreshTokenExpired, errs.KindUnauthenticated, "That refresh token has expired.").AsRetryable()
	ErrRefreshTokenReuse          = errs.New(CodeRefreshTokenReuse, errs.KindUnauthenticated, "That refresh token was already used; all related tokens have been revoked.")
	ErrIDInvalid                  = errs.New("oidc.id_invalid", errs.KindInvalid, "That ID is invalid.")
	// Grant & device administration.
	ErrGrantNotFound  = errs.New(CodeGrantNotFound, errs.KindNotFound, "We couldn't find that grant.")
	ErrDeviceNotFound = errs.New(CodeDeviceNotFound, errs.KindNotFound, "We couldn't find that device authorization.")
	// Device Authorization Grant (RFC 8628) user-code flow.
	ErrUserCodeInvalid          = errs.New("oidc.user_code_invalid", errs.KindNotFound, "That code isn't recognized.")
	ErrUserCodeExpired          = errs.New(CodeUserCodeExpired, errs.KindInvalid, "That code has expired. Request a new one on your device.")
	ErrUserCodeRequired         = errs.New("oidc.user_code_required", errs.KindInvalid, "Enter the code shown on your device.")
	ErrDeviceAlreadyDecided     = errs.New(CodeDeviceAlreadyDecided, errs.KindConflict, "This device authorization has already been decided.")
	ErrUserOrganizationMismatch = errs.New(CodeUserOrganizationMismatch, errs.KindForbidden, "You don't belong to this client's organization.")
	// CIBA backchannel sign-in requests.
	ErrCIBARequestNotFound       = errs.New("oidc.ciba_request_not_found", errs.KindNotFound, "We couldn't find that sign-in request.")
	ErrCIBARequestNotOwned       = errs.New(CodeCIBARequestNotOwned, errs.KindForbidden, "That sign-in request isn't yours.")
	ErrCIBARequestExpired        = errs.New("oidc.ciba_request_expired", errs.KindInvalid, "That sign-in request has expired.")
	ErrCIBARequestAlreadyDecided = errs.New(CodeCIBARequestAlreadyDecided, errs.KindConflict, "That sign-in request has already been decided.")
	// Client secret rotation & shadow-AI review.
	ErrPublicClientNoSecret = errs.New(CodePublicClientNoSecret, errs.KindUnprocessable, "Public clients have no secret to rotate.")
	ErrReviewerRequired     = errs.New("oidc.reviewer_required", errs.KindUnauthenticated, "This review must be attributed to a signed-in user.")
)
