package oidc

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.serverMetadata(r))
}

// authorizationServerMetadata (GET /.well-known/oauth-authorization-server) is
// the RFC 8414 document an OAuth-only client, or a model-context-protocol
// client following the protected-resource document, configures itself from.
// The same document as the OpenID configuration, so the two can't disagree.
func (h *Handler) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.serverMetadata(r))
}

// serverMetadata is the authorization server's metadata, for the request's
// host.
func (h *Handler) serverMetadata(r *http.Request) map[string]any {
	base := httpx.PublicOrigin(r, h.PublicBaseURL)
	return map[string]any{
		// The issuer the tokens and authorization responses carry, which a
		// relying party compares them with.
		"issuer":                                h.Service.issuer.JWTIssuer(),
		"authorization_endpoint":                base + "/v1/oauth/authorize",
		"token_endpoint":                        base + "/v1/oauth/token-code",
		"device_authorization_endpoint":         base + "/v1/oauth/device_authorization",
		"userinfo_endpoint":                     base + "/v1/oauth/userinfo",
		"jwks_uri":                              base + "/.well-known/jwks.json",
		"revocation_endpoint":                   base + "/oauth/revoke",
		"introspection_endpoint":                base + "/oauth/introspect",
		"end_session_endpoint":                  base + "/v1/oauth/logout",
		"response_types_supported":              responseTypesSupported,
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{h.Service.issuer.Alg()},
		"scopes_supported":                      scopesSupported,
		"claims_supported":                      claimsSupported(),
		"prompt_values_supported":               promptValuesSupported,
		"response_modes_supported":              responseModesSupported,
		"request_parameter_supported":           false,
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"request_uri_parameter_supported":       false,
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", grantTypeTokenExchange, grantTypeCIBA},
		// OpenID CIBA — poll mode only (no ping/push notification_endpoint).
		"backchannel_token_delivery_modes_supported": []string{"poll"},
		"backchannel_authentication_endpoint":        base + "/v1/oauth/bc-authorize",
		"backchannel_user_code_parameter_supported":  false,
		"code_challenge_methods_supported":           []string{"S256"},
		// Client authentication: a secret by Basic or form everywhere; "none"
		// (a public client) only where it may call, and introspection never.
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		// RFC 8707 — Resource Indicators
		"resource_indicators_supported": true,
		// RFC 9207 — the authorization response carries an `iss` parameter.
		"authorization_response_iss_parameter_supported": true,
		// Non-standard: agent tokens describe themselves with the actor_type and
		// agent_id claims rather than a sub prefix, which would break token exchange.
		"actor_types_supported": []string{"user", "service", "agent"},
	}
}

// scopesSupported is every scope an application may request.
var scopesSupported = []string{"openid", "profile", "email", "phone"}

// protectedResourceMetadata implements RFC 9728 §3 — OAuth 2.0 Protected
// Resource Metadata. MCP authorization servers must advertise this document
// so MCP clients can discover the resource's authorization server and
// supported token types without out-of-band configuration.
func (h *Handler) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	base := httpx.PublicOrigin(r, h.PublicBaseURL)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"resource":                              base,
		"authorization_servers":                 []string{base},
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{h.Service.issuer.Alg()},
		"resource_documentation":                "https://docs.qeet.in/id/api-reference",
		"scopes_supported":                      scopesSupported,
	})
}

// jwks publishes the public signing keys (active + any retired key still in its
// rotation grace window) so any relying party can verify Qeet-issued ID/access
// tokens. Keys are ES256 over EC P-256; each `kid` matches the token's `kid`
// header (an RFC 7638 JWK thumbprint).
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"keys": h.Service.issuer.JWKS()})
}
