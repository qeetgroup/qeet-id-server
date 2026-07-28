package httpx

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// OIDC / OAuth2 provider code→status mappings. Registered from init() so the
// federation/oidc bounded context owns its own mappings without editing the
// shared error_status.go. Each code maps to the SAME status as the generic
// sentinel it replaced.
func init() {
	registerStatuses(map[string]int{
		// Client identity & authentication.
		errs.CodeOIDCClientUnknown:    http.StatusBadRequest,
		errs.CodeOIDCClientNotFound:   http.StatusNotFound,
		errs.CodeOIDCClientAuthFailed: http.StatusUnauthorized,

		// Redirect URIs & scopes.
		errs.CodeOIDCRedirectURIInvalid:  http.StatusBadRequest,
		errs.CodeOIDCRedirectURIMismatch: http.StatusBadRequest,
		errs.CodeOIDCScopeNotPermitted:   http.StatusBadRequest,
		errs.CodeOIDCScopeExceedsSubject: http.StatusForbidden,

		// Grant types.
		errs.CodeOIDCGrantTypeUnsupported: http.StatusBadRequest,
		errs.CodeOIDCGrantTypeNotAllowed:  http.StatusForbidden,

		// Authorization code + PKCE.
		errs.CodeOIDCAuthCodeInvalid:                http.StatusBadRequest,
		errs.CodeOIDCAuthCodeUsed:                   http.StatusBadRequest,
		errs.CodeOIDCAuthCodeExpired:                http.StatusBadRequest,
		errs.CodeOIDCCodeVerifierRequired:           http.StatusBadRequest,
		errs.CodeOIDCCodeVerifierInvalid:            http.StatusBadRequest,
		errs.CodeOIDCCodeChallengeMethodUnsupported: http.StatusBadRequest,

		// Token exchange (RFC 8693) subject/actor tokens.
		errs.CodeOIDCSubjectTokenRequired:          http.StatusBadRequest,
		errs.CodeOIDCSubjectTokenTypeUnsupported:   http.StatusBadRequest,
		errs.CodeOIDCSubjectTokenInvalid:           http.StatusUnauthorized,
		errs.CodeOIDCSubjectTokenNoSubject:         http.StatusUnauthorized,
		errs.CodeOIDCRequestedTokenTypeUnsupported: http.StatusBadRequest,
		errs.CodeOIDCActorTokenTypeUnsupported:     http.StatusBadRequest,
		errs.CodeOIDCActorTokenInvalid:             http.StatusUnauthorized,

		// Refresh tokens.
		errs.CodeOIDCRefreshTokenRequired:       http.StatusBadRequest,
		errs.CodeOIDCRefreshTokenInvalid:        http.StatusUnauthorized,
		errs.CodeOIDCRefreshTokenClientMismatch: http.StatusUnauthorized,
		errs.CodeOIDCRefreshTokenRevoked:        http.StatusUnauthorized,
		errs.CodeOIDCRefreshTokenExpired:        http.StatusUnauthorized,
		errs.CodeOIDCRefreshTokenReuse:          http.StatusUnauthorized,

		// Request shape & path parameters.
		errs.CodeOIDCFormInvalid:     http.StatusBadRequest,
		errs.CodeOIDCTenantIDInvalid: http.StatusBadRequest,
		errs.CodeOIDCTenantMismatch:  http.StatusForbidden,
		errs.CodeOIDCIDInvalid:       http.StatusBadRequest,

		// Grant & device administration.
		errs.CodeOIDCGrantNotFound:  http.StatusNotFound,
		errs.CodeOIDCDeviceNotFound: http.StatusNotFound,

		// Device Authorization Grant (RFC 8628) user-code flow.
		errs.CodeOIDCUserCodeInvalid:      http.StatusNotFound,
		errs.CodeOIDCUserCodeExpired:      http.StatusBadRequest,
		errs.CodeOIDCUserCodeRequired:     http.StatusBadRequest,
		errs.CodeOIDCDeviceAlreadyDecided: http.StatusConflict,
		errs.CodeOIDCUserTenantMismatch:   http.StatusForbidden,

		// CIBA backchannel sign-in requests.
		errs.CodeOIDCCIBARequestNotFound:       http.StatusNotFound,
		errs.CodeOIDCCIBARequestNotOwned:       http.StatusForbidden,
		errs.CodeOIDCCIBARequestExpired:        http.StatusBadRequest,
		errs.CodeOIDCCIBARequestAlreadyDecided: http.StatusConflict,

		// Client secret rotation & shadow-AI review.
		errs.CodeOIDCPublicClientNoSecret: http.StatusUnprocessableEntity,
		errs.CodeOIDCReviewerRequired:     http.StatusUnauthorized,
	})
}
