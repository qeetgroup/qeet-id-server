package oidc

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// token is the OAuth token endpoint (RFC 6749 §3.2) for every grant: it reads
// the client's credentials once, from the form or HTTP Basic, runs the grant
// grant_type names and answers a refusal in the RFC 6749 §5.2 shape.
func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		writeTokenError(w, r, err)
		return
	}
	// RFC 8707 §2 — validate the optional resource indicator if present.
	// The resource must be an absolute URI with a scheme; fragment components
	// are forbidden. An unrecognised or malformed value yields invalid_target.
	resource := r.Form.Get("resource")
	if resource != "" {
		u, parseErr := url.Parse(resource)
		if parseErr != nil || !u.IsAbs() || u.Fragment != "" {
			writeTokenError(w, r, oauthErr("invalid_target", "resource must be an absolute URI without a fragment"))
			return
		}
	}
	grantType := r.Form.Get("grant_type")
	// Explicitly refused, never silently dropped: these grants bind no resource.
	if resource != "" && (grantType == grantTypeDeviceCode || grantType == grantTypeCIBA) {
		writeTokenError(w, r, oauthErr("invalid_target", "resource indicators aren't supported on the device and backchannel flows"))
		return
	}
	if resource != "" && grantType == grantTypeClientCredentials {
		writeTokenError(w, r, oauthErr("invalid_target", "resource indicators aren't supported on the client_credentials grant"))
		return
	}
	var resp *TokenResponse
	switch grantType {
	case "authorization_code":
		resp, err = h.Service.ExchangeCode(r.Context(),
			clientID, clientSecret,
			r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier"), resource)
	case "refresh_token":
		resp, err = h.Service.RefreshToken(r.Context(),
			clientID, clientSecret, r.Form.Get("refresh_token"), resource)
	case grantTypeTokenExchange:
		resp, err = h.Service.TokenExchange(r.Context(),
			clientID, clientSecret,
			r.Form.Get("subject_token"), r.Form.Get("subject_token_type"),
			r.Form.Get("requested_token_type"), r.Form.Get("scope"),
			r.Form.Get("actor_token"), r.Form.Get("actor_token_type"), resource)
	case grantTypeDeviceCode:
		// RFC 8628 §3.4 polling: a confidential client authenticates; for a public
		// one the device_code is the proof.
		resp, err = h.Service.DeviceToken(r.Context(), clientID, clientSecret, r.Form.Get("device_code"), httpx.ClientIP(r))
	case grantTypeCIBA:
		// OpenID CIBA §10 polling, answered like device_code polling.
		resp, err = h.Service.BackchannelToken(r.Context(), clientID, clientSecret, r.Form.Get("auth_req_id"))
	case grantTypeClientCredentials:
		// A machine identity's own token; scope is ignored, as it gets every
		// scope it holds.
		resp, err = h.Service.ClientCredentials(r.Context(), clientID, clientSecret)
	case "":
		err = oauthErr("invalid_request", "grant_type is required")
	default:
		err = ErrGrantTypeUnsupported
	}
	if err != nil {
		writeTokenError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// tokenErrorCodes are the RFC 6749 §5.2 codes of the grants' own errors; any
// other client error is invalid_request.
var tokenErrorCodes = map[string]string{
	errs.CodeOIDCClientAuthFailed:        "invalid_client",
	CodeGrantTypeUnsupported:             "unsupported_grant_type",
	CodeGrantTypeNotAllowed:              "unauthorized_client",
	CodeAuthCodeInvalid:                  "invalid_grant",
	CodeAuthCodeUsed:                     "invalid_grant",
	CodeAuthCodeExpired:                  "invalid_grant",
	CodeRedirectURIMismatch:              "invalid_grant",
	CodeCodeChallengeRequired:            "invalid_grant",
	CodeCodeChallengeMethodUnsupported:   "invalid_grant",
	CodeCodeVerifierRequired:             "invalid_grant",
	CodeCodeVerifierInvalid:              "invalid_grant",
	CodeRefreshTokenInvalid:              "invalid_grant",
	CodeRefreshTokenClientMismatch:       "invalid_grant",
	CodeRefreshTokenRevoked:              "invalid_grant",
	CodeRefreshTokenExpired:              "invalid_grant",
	CodeRefreshTokenReuse:                "invalid_grant",
	errs.CodeAuthAccountSuspended:        "invalid_grant",
	CodeUserOrganizationMismatch:         "invalid_grant",
	CodeScopeExceedsSubject:              "invalid_scope",
	errs.CodePrincipalInvalidCredentials: "invalid_client",
	errs.CodePrincipalDisabled:           "unauthorized_client",
	errs.CodeAgentTokenInvalid:           "invalid_client",
	errs.CodeAgentInactive:               "unauthorized_client",
}

// writeTokenError answers a failed token request in the RFC 6749 §5.2 shape, with a Basic challenge on
// invalid_client when the client sent Basic credentials. Every invalid_client reads the same, so the
// answer doesn't tell what client, if any, the id names; an internal error keeps the generic answer.
func writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauthError
	if !errors.As(err, &oe) {
		e := errs.As(err)
		if e == nil || e.Code == errs.CodeInternal {
			httpx.WriteError(w, r, err)
			return
		}
		code, ok := tokenErrorCodes[e.Code]
		if !ok {
			code = "invalid_request"
		}
		description := e.Message
		if code == "invalid_client" {
			description = errs.ErrOIDCClientAuthFailed.Message
		}
		oe = oauthErr(code, description)
	}
	if _, _, basic := r.BasicAuth(); basic && oe.Code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Basic realm="qeet"`)
	}
	writeOAuthError(w, oe)
}

// clientCreds parses the form and the OAuth client credentials in it or in
// HTTP Basic auth (the two RFC 6749 §2.3.1 mechanisms), Basic first. Every
// client-authenticated endpoint reads them here.
func (h *Handler) clientCreds(r *http.Request) (id, secret string, err error) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		return "", "", err
	}
	id = r.Form.Get("client_id")
	secret = r.Form.Get("client_secret")
	if u, p, has := httpx.ClientBasicAuth(r); has {
		id, secret = u, p
	}
	return id, secret, nil
}

// revoke is the RFC 7009 token-revocation endpoint. It always answers 200 with
// an empty body on success (including for unknown tokens).
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RevokeToken(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint")); err != nil {
		var oe *oauthError
		if errors.As(err, &oe) {
			writeOAuthError(w, oe)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// introspect is the RFC 7662 token-introspection endpoint.
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := h.clientCreds(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	resp, err := h.Service.Introspect(r.Context(), clientID, clientSecret, r.Form.Get("token"), r.Form.Get("token_type_hint"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}
